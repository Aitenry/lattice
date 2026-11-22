import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react'
import enUS from 'antd/locale/en_US'
import zhCN from 'antd/locale/zh_CN'
import dayjs from 'dayjs'
import 'dayjs/locale/zh-cn'
import { ZH_MESSAGES } from './locales.zh'

/**
 * Console localisation (English is the source language, Chinese is an overlay).
 *
 * - English strings live inline at the call site: `t('Users')`. The English text is
 *   itself the lookup key, so a missing overlay degrades to readable English instead
 *   of a raw key name.
 * - Chinese overlays live in `locales.zh.ts`; `t()` returns the overlay when the
 *   active locale is `zh`.
 * - Interpolation: `t('Loaded {count} rows', { count: 12 })`.
 * - The choice is persisted in localStorage and defaults to English; the document
 *   `<html lang>` and dayjs locale follow it.
 */
export type Locale = 'en' | 'zh'

export const LOCALE_STORAGE_KEY = 'lattice.admin.locale'

export type Placeholders = Record<string, string | number>
export type Translate = (source: string, placeholders?: Placeholders) => string

interface I18nContextValue {
  locale: Locale
  setLocale: (locale: Locale) => void
  toggleLocale: () => void
  t: Translate
  antdLocale: typeof enUS
}

function interpolate(template: string, placeholders?: Placeholders): string {
  if (!placeholders) return template
  return template.replace(/\{(\w+)\}/g, (match, key: string) =>
    Object.prototype.hasOwnProperty.call(placeholders, key) ? String(placeholders[key]) : match,
  )
}

const I18nContext = createContext<I18nContextValue | null>(null)

function persist(locale: Locale) {
  try {
    localStorage.setItem(LOCALE_STORAGE_KEY, locale)
  } catch {
    /* private mode: the choice only lasts for this session */
  }
}

function readInitialLocale(): Locale {
  try {
    const saved = localStorage.getItem(LOCALE_STORAGE_KEY)
    if (saved === 'en' || saved === 'zh') return saved
  } catch {
    /* localStorage unavailable: fall through to the default */
  }
  return 'en'
}

export function I18nProvider({ children }: { children: ReactNode }) {
  const [locale, setLocaleState] = useState<Locale>(readInitialLocale)

  const setLocale = useCallback((next: Locale) => {
    setLocaleState(next)
    persist(next)
  }, [])

  const toggleLocale = useCallback(() => {
    setLocaleState((current) => {
      const next: Locale = current === 'en' ? 'zh' : 'en'
      persist(next)
      return next
    })
  }, [])

  const t = useMemo<Translate>(
    () => (source, placeholders) =>
      interpolate(locale === 'zh' ? (ZH_MESSAGES[source] ?? source) : source, placeholders),
    [locale],
  )

  useEffect(() => {
    document.documentElement.lang = locale === 'zh' ? 'zh-CN' : 'en'
    dayjs.locale(locale === 'zh' ? 'zh-cn' : 'en')
  }, [locale])

  const value = useMemo<I18nContextValue>(
    () => ({ locale, setLocale, toggleLocale, t, antdLocale: locale === 'zh' ? zhCN : enUS }),
    [locale, setLocale, toggleLocale, t],
  )

  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>
}

export function useI18n(): I18nContextValue {
  const value = useContext(I18nContext)
  if (!value) throw new Error('useI18n must be used inside <I18nProvider>')
  return value
}
