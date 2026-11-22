import { theme as antdAlgorithms, type ThemeConfig } from 'antd'

/**
 * Console design tokens (single source).
 *
 * Visual decisions: dark slate sidebar + light grey content area + corporate blue primary.
 * - The sidebar answers "where am I" and uses low-saturation dark tones to recede;
 * - The content area carries data in white cards, separated by 1px borders and very light
 *   shadows instead of decoration;
 * - The primary colour is only used for primary actions, the selected nav item and key
 *   numbers; everything else stays neutral.
 *
 * Since v0.9 there are **light/dark themes** (the moon/sun button next to "Guide" toggles
 * them; the choice is stored in localStorage):
 * - antd component colours come from `buildAntdTheme(mode)` below (dark uses antd's darkAlgorithm);
 * - this file also provides `CSS_VAR` variable names → values for both themes; styles.css
 *   only references the variables;
 * - the only exception: the sidebar brand area and the dark decorative panel on the login
 *   page's left side **stay dark in both themes**; their fixed colours live in that block of
 *   styles.css (they do not switch and therefore raise no contrast issues);
 * - new components must not hard-code hex colours; only semantic status colours may use tokens.
 */

export const BRAND = {
  name: 'Lattice',
  fullName: 'Lattice Admin Console',
  slogan: 'End-to-end encrypted messaging platform · Operations and compliance console',
}

/** Light/dark theme */
export type ThemeMode = 'light' | 'dark'

/**
 * CSS variables used outside antd (styles.css shell, login page, stat-card icon
 * backgrounds, ...).
 *
 * Keys are CSS variable suffixes (`--bg-layout`, ...); values are `[light, dark]` pairs.
 * Change colours only here; a hex colour inside styles.css is a bug.
 */
export const CSS_VAR: Record<string, [light: string, dark: string]> = {
  // Background layers: layout < card < elevated (overlays are one step lighter in dark mode)
  'bg-layout': ['#f5f7fa', '#0b1220'],
  'bg-card': ['#ffffff', '#111a2c'],
  'bg-elevated': ['#ffffff', '#162034'],
  'bg-soft': ['#f8fafc', '#162034'],
  'bg-hover': ['#f1f5f9', '#1b2740'],
  'bg-active': ['#e2e8f0', '#24324a'],

  // Text
  text: ['#1f2733', '#e6edf7'],
  'text-strong': ['#111827', '#f4f8ff'],
  'text-2': ['#5b6675', '#a7b4c8'],
  'text-3': ['#8a94a3', '#7d8ba3'],
  'text-4': ['#a8b1bf', '#64748b'],

  // Borders
  border: ['#e2e6ec', '#24324a'],
  'border-soft': ['#eef1f5', '#1b2740'],

  // Primary / semantic colours
  primary: ['#2563eb', '#60a5fa'],
  'primary-strong': ['#1d4ed8', '#3b82f6'],
  ok: ['#16a34a', '#22c55e'],
  warn: ['#d97706', '#f59e0b'],
  bad: ['#dc2626', '#ef4444'],

  // Avatar placeholder (same palette as the account area)
  'avatar-bg': ['#dbeafe', '#1e3a5f'],
  'avatar-fg': ['#1d4ed8', '#93c5fd'],

  // Scrollbar
  'scroll-thumb': ['#cbd5e1', '#334155'],
  'scroll-thumb-hover': ['#94a3b8', '#475569'],

  // Stat-card icon backgrounds (StatCard tone)
  'tone-blue-bg': ['#eff6ff', 'rgba(59, 130, 246, 0.18)'],
  'tone-blue-fg': ['#1d4ed8', '#93c5fd'],
  'tone-green-bg': ['#f0fdf4', 'rgba(34, 197, 94, 0.16)'],
  'tone-green-fg': ['#15803d', '#86efac'],
  'tone-orange-bg': ['#fff7ed', 'rgba(245, 158, 11, 0.16)'],
  'tone-orange-fg': ['#c2410c', '#fcd34d'],
  'tone-red-bg': ['#fef2f2', 'rgba(239, 68, 68, 0.16)'],
  'tone-red-fg': ['#b91c1c', '#fca5a5'],
  'tone-slate-bg': ['#f1f5f9', 'rgba(148, 163, 184, 0.16)'],
  'tone-slate-fg': ['#475569', '#cbd5e1'],
  'tone-violet-bg': ['#f5f3ff', 'rgba(139, 92, 246, 0.18)'],
  'tone-violet-fg': ['#6d28d9', '#c4b5fd'],

  // Code blocks (dark in both themes so reading code is easy on the eyes)
  'code-bg': ['#0f172a', '#0a101c'],
  'code-fg': ['#cbd5e1', '#cbd5e1'],
}

/** Builds the `:root { --x:... }` / `[data-theme='dark'] { --x:... }` CSS text (kept for docs/validation) */
export function cssVarsBlock(mode: ThemeMode): string {
  const idx = mode === 'dark' ? 1 : 0
  return Object.entries(CSS_VAR)
    .map(([k, v]) => `  --${k}: ${v[idx]};`)
    .join('\n')
}

// ---------------------------------------------------------------------------
// antd theme
// ---------------------------------------------------------------------------

/** Light theme (the original look, unchanged) */
export const lightTheme: ThemeConfig = {
  token: {
    colorPrimary: '#2563eb',
    colorInfo: '#2563eb',
    colorLink: '#2563eb',
    colorSuccess: '#16a34a',
    colorWarning: '#d97706',
    colorError: '#dc2626',
    colorBgLayout: '#f5f7fa',
    colorBgContainer: '#ffffff',
    colorBgElevated: '#ffffff',
    colorBorder: '#e2e6ec',
    colorBorderSecondary: '#eef1f5',
    colorText: '#1f2733',
    colorTextSecondary: '#5b6675',
    colorTextTertiary: '#8a94a3',
    borderRadius: 8,
    controlHeight: 34,
    fontSize: 14,
    fontFamily:
      "-apple-system, BlinkMacSystemFont, 'Segoe UI', 'PingFang SC', 'Hiragino Sans GB', 'Microsoft YaHei', Roboto, Helvetica, Arial, sans-serif",
    boxShadowTertiary: '0 1px 2px rgba(16, 24, 40, 0.04)',
  },
  components: {
    Layout: {
      siderBg: '#0f172a',
      headerBg: '#ffffff',
      headerHeight: 60,
      headerPadding: '0 20px',
      bodyBg: '#f5f7fa',
    },
    Menu: {
      darkItemBg: '#0f172a',
      darkSubMenuItemBg: '#0f172a',
      darkItemColor: 'rgba(226, 232, 240, 0.72)',
      darkItemHoverBg: 'rgba(148, 163, 184, 0.12)',
      darkItemSelectedBg: '#2563eb',
      darkItemSelectedColor: '#ffffff',
      itemHeight: 40,
      itemBorderRadius: 8,
      itemMarginInline: 10,
      itemMarginBlock: 2,
      iconSize: 16,
      collapsedIconSize: 18,
    },
    Card: {
      headerHeight: 48,
      headerFontSize: 14,
      headerBg: 'transparent',
      paddingLG: 20,
      borderRadiusLG: 10,
    },
    Table: {
      headerBg: '#f8fafc',
      headerColor: '#5b6675',
      headerSplitColor: 'transparent',
      rowHoverBg: '#f8fafc',
      cellPaddingBlockSM: 10,
      borderColor: '#eef1f5',
    },
    Button: { fontWeight: 500, defaultShadow: 'none', primaryShadow: 'none' },
    Modal: { titleFontSize: 16, contentBg: '#ffffff' },
    Descriptions: { labelBg: '#f8fafc', titleMarginBottom: 12 },
    Tabs: { horizontalItemPadding: '10px 0', titleFontSize: 14 },
    Statistic: { titleFontSize: 13 },
  },
}

/**
 * Dark theme: the content area uses dark slate blue (one step lighter than the sidebar so
 * cards keep their hierarchy); semantic colours are brightened one notch to stay readable
 * on dark backgrounds.
 */
export const darkTheme: ThemeConfig = {
  algorithm: antdAlgorithms.darkAlgorithm,
  token: {
    colorPrimary: '#3b82f6',
    colorInfo: '#3b82f6',
    colorLink: '#60a5fa',
    colorSuccess: '#22c55e',
    colorWarning: '#f59e0b',
    colorError: '#ef4444',
    colorBgLayout: '#0b1220',
    colorBgContainer: '#111a2c',
    colorBgElevated: '#162034',
    colorBorder: '#24324a',
    colorBorderSecondary: '#1b2740',
    colorText: '#e6edf7',
    colorTextSecondary: '#a7b4c8',
    colorTextTertiary: '#7d8ba3',
    borderRadius: 8,
    controlHeight: 34,
    fontSize: 14,
    fontFamily:
      "-apple-system, BlinkMacSystemFont, 'Segoe UI', 'PingFang SC', 'Hiragino Sans GB', 'Microsoft YaHei', Roboto, Helvetica, Arial, sans-serif",
    boxShadowTertiary: '0 1px 2px rgba(0, 0, 0, 0.4)',
  },
  components: {
    Layout: {
      siderBg: '#0a101c',
      headerBg: '#0f172a',
      headerHeight: 60,
      headerPadding: '0 20px',
      bodyBg: '#0b1220',
    },
    Menu: {
      darkItemBg: '#0a101c',
      darkSubMenuItemBg: '#0a101c',
      darkItemColor: 'rgba(203, 213, 225, 0.72)',
      darkItemHoverBg: 'rgba(148, 163, 184, 0.16)',
      darkItemSelectedBg: '#2563eb',
      darkItemSelectedColor: '#ffffff',
      itemHeight: 40,
      itemBorderRadius: 8,
      itemMarginInline: 10,
      itemMarginBlock: 2,
      iconSize: 16,
      collapsedIconSize: 18,
    },
    Card: {
      headerHeight: 48,
      headerFontSize: 14,
      headerBg: 'transparent',
      paddingLG: 20,
      borderRadiusLG: 10,
    },
    Table: {
      headerBg: '#162034',
      headerColor: '#a7b4c8',
      headerSplitColor: 'transparent',
      rowHoverBg: '#18233a',
      cellPaddingBlockSM: 10,
      borderColor: '#1b2740',
    },
    Button: { fontWeight: 500, defaultShadow: 'none', primaryShadow: 'none' },
    Modal: { titleFontSize: 16, contentBg: '#111a2c' },
    Descriptions: { labelBg: '#162034', titleMarginBottom: 12 },
    Tabs: { horizontalItemPadding: '10px 0', titleFontSize: 14 },
    Statistic: { titleFontSize: 13 },
  },
}

export function buildAntdTheme(mode: ThemeMode): ThemeConfig {
  return mode === 'dark' ? darkTheme : lightTheme
}

/** Backwards compatibility (the console used to be light-only; main.tsx now uses buildAntdTheme) */
export const antdTheme = lightTheme
