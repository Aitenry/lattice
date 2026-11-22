import {
  createContext,
  useCallback,
  useContext,
  useLayoutEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react'
import { ConfigProvider } from 'antd'
import { CSS_VAR, buildAntdTheme, type ThemeMode } from '@/theme'
import { useI18n } from '@/i18n'

/**
 * Light/dark theme context (single source).
 *
 * - Light by default (keeps the console's visual baseline stable instead of flipping
 *   with the OS setting). After the user clicks the moon/sun the choice is written to
 *   localStorage and reused next time;
 * - Toggle: the moon/sun button in the top bar (AppLayout) or the same button in the
 *   login page's top-right corner;
 * - Side effects: tag `<html data-theme="light|dark">` and inject the `theme.ts` CSS_VAR
 *   values as inline variables on `<html>` (styles.css only references them, never
 *   re-copies colours); antd components switch through ConfigProvider's algorithm/token;
 * - `useLayoutEffect` applies the colours before the browser paints, so switching theme
 *   does not flash white.
 */

const STORAGE_KEY = 'lattice.admin.theme'

/** Single source for theme colours: expand CSS_VAR into `--x: value` on <html>; styles.css uses var() */
function applyCssVars(mode: ThemeMode) {
  const root = document.documentElement
  const index = mode === 'dark' ? 1 : 0
  for (const [name, pair] of Object.entries(CSS_VAR)) {
    root.style.setProperty(`--${name}`, pair[index])
  }
}

interface ThemeContextValue {
  mode: ThemeMode
  setMode: (mode: ThemeMode) => void
  toggle: () => void
}

const ThemeModeContext = createContext<ThemeContextValue>({
  mode: 'light',
  setMode: () => undefined,
  toggle: () => undefined,
})

function readInitialMode(): ThemeMode {
  try {
    const saved = localStorage.getItem(STORAGE_KEY)
    if (saved === 'light' || saved === 'dark') return saved
  } catch {
    /* localStorage unavailable (private mode): fall back to light */
  }
  return 'light'
}

export function ThemeModeProvider({ children }: { children: ReactNode }) {
  const [mode, setModeState] = useState<ThemeMode>(readInitialMode)
  const { antdLocale } = useI18n()

  useLayoutEffect(() => {
    const root = document.documentElement
    root.dataset.theme = mode
    root.style.colorScheme = mode
    applyCssVars(mode)
    try {
      localStorage.setItem(STORAGE_KEY, mode)
    } catch {
      /* cannot persist: the choice only lasts for this session */
    }
  }, [mode])

  const setMode = useCallback((next: ThemeMode) => setModeState(next), [])
  const toggle = useCallback(() => setModeState((m) => (m === 'dark' ? 'light' : 'dark')), [])
  const ctx = useMemo(() => ({ mode, setMode, toggle }), [mode, setMode, toggle])

  return (
    <ThemeModeContext.Provider value={ctx}>
      <ConfigProvider locale={antdLocale} theme={buildAntdTheme(mode)}>
        {children}
      </ConfigProvider>
    </ThemeModeContext.Provider>
  )
}

export function useThemeMode(): ThemeContextValue {
  return useContext(ThemeModeContext)
}
