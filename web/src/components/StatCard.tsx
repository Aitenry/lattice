import type { ReactNode } from 'react'

/**
 * Metric card: one number plus one plain-language explanation.
 * "How to judge whether this number is good" belongs in `hint`; do not make people guess.
 *
 * Colours come from `.stat-icon.tone-*` in styles.css (values live in `CSS_VAR` in
 * theme.ts, one set per theme), so the component itself contains no hex colours.
 */
export function StatCard(props: {
  label: string
  value: ReactNode
  hint?: ReactNode
  icon?: ReactNode
  tone?: 'blue' | 'green' | 'orange' | 'red' | 'slate' | 'violet'
  small?: boolean
}) {
  const tone = props.tone ?? 'blue'
  return (
    <div className="stat-card">
      <div className="stat-head">
        <span className="stat-label">{props.label}</span>
        {props.icon ? <span className={`stat-icon tone-${tone}`}>{props.icon}</span> : null}
      </div>
      <div className={props.small ? 'stat-value small' : 'stat-value'}>{props.value}</div>
      {props.hint ? <div className="stat-hint">{props.hint}</div> : null}
    </div>
  )
}
