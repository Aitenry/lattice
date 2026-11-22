/**
 * CSV export (PL-16 16.12; ② §9.3 "export: audit/message metadata to CSV (paged fetch,
 * aggregated in the frontend)").
 *
 * Why paged instead of one full fetch: every admin list caps page/page_size, and a full
 * export would saturate the database. This fetches 200 rows per page, caps at 10,000
 * rows and tells the UI when it truncated (never silently drops rows).
 */

/** Cell escaping: values containing commas/quotes/newlines are quoted; inner quotes are doubled */
function escapeCell(value: unknown): string {
  if (value == null) return ''
  const s = typeof value === 'object' ? JSON.stringify(value) : String(value)
  if (/[",\n\r]/.test(s)) return `"${s.replace(/"/g, '""')}"`
  return s
}

export function toCsv(headers: string[], rows: unknown[][]): string {
  const lines = [headers.map(escapeCell).join(','), ...rows.map((r) => r.map(escapeCell).join(','))]
  // UTF-8 BOM: Excel opens UTF-8 text without garbling it
  return '\uFEFF' + lines.join('\r\n') + '\r\n'
}

export function downloadText(filename: string, content: string, mime = 'text/csv;charset=utf-8'): void {
  const blob = new Blob([content], { type: mime })
  const url = URL.createObjectURL(blob)
  try {
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    a.style.display = 'none'
    document.body.appendChild(a)
    a.click()
    a.remove()
  } finally {
    // Release once the browser has started the download
    window.setTimeout(() => URL.revokeObjectURL(url), 1000)
  }
}

export const CSV_PAGE_SIZE = 200
export const CSV_MAX_ROWS = 10_000

export interface CsvPage<T> {
  items: T[]
  total: number
}

/**
 * Fetch pages and aggregate. Returns { rows, truncated }; when truncated the UI must say
 * so instead of pretending the export is complete. A failed fetch throws (the caller
 * shows the error and no half-written file is produced).
 */
export async function collectAllPages<T>(
  fetchPage: (page: number, pageSize: number) => Promise<CsvPage<T>>,
  maxRows = CSV_MAX_ROWS,
  pageSize = CSV_PAGE_SIZE
): Promise<{ rows: T[]; total: number; truncated: boolean }> {
  const first = await fetchPage(1, pageSize)
  const all = [...(first.items ?? [])]
  const total = first.total ?? all.length
  let page = 2
  while (all.length < Math.min(total, maxRows) && page <= Math.ceil(total / pageSize)) {
    const next = await fetchPage(page, pageSize)
    const items = next.items ?? []
    if (items.length === 0) break
    all.push(...items)
    page += 1
  }
  const truncated = all.length > maxRows || total > maxRows
  return { rows: all.slice(0, maxRows), total, truncated }
}

/** Filename prefixed with local time (avoids collisions between tabs) */
export function csvFilename(prefix: string): string {
  const d = new Date()
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${prefix}-${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}-${pad(d.getHours())}${pad(d.getMinutes())}${pad(d.getSeconds())}.csv`
}
