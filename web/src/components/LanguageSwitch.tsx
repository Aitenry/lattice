import { Segmented } from 'antd'
import { useI18n, type Locale } from '@/i18n'

/**
 * Language switch used by the console shell and the login page.
 * English is the default locale; the choice is persisted by the i18n provider.
 */
export default function LanguageSwitch({ size = 'middle' }: { size?: 'small' | 'middle' | 'large' }) {
  const { locale, setLocale } = useI18n()

  return (
    <Segmented
      size={size}
      value={locale}
      onChange={(value) => setLocale(value as Locale)}
      options={[
        { label: 'English', value: 'en' },
        { label: '简体中文', value: 'zh' },
      ]}
      aria-label="Language"
      data-testid="locale-switch"
    />
  )
}
