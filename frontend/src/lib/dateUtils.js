/**
 * Date and Time utilities for CyberShield AI.
 * Ensures timestamps from the backend are consistently parsed as UTC and formatted in
 * the user's local timezone (e.g. IST / Indian Standard Time, UTC+5:30).
 */

export function parseDate(ts) {
  if (!ts) return new Date()
  if (ts instanceof Date) return ts
  if (typeof ts === 'string') {
    // If string has date-time format without 'Z' or timezone offset, append 'Z' so JS treats it as UTC
    if (!ts.endsWith('Z') && !/[+-]\d{2}:\d{2}$/.test(ts)) {
      return new Date(ts + 'Z')
    }
  }
  return new Date(ts)
}

/**
 * Format timestamp as HH:MM:SS.mmm in user's local timezone (e.g. IST).
 */
export function formatLocalTime(ts, includeMs = true) {
  const d = parseDate(ts)
  if (Number.isNaN(d.getTime())) return '—'
  const hh = d.getHours().toString().padStart(2, '0')
  const mm = d.getMinutes().toString().padStart(2, '0')
  const ss = d.getSeconds().toString().padStart(2, '0')
  if (includeMs) {
    const ms = d.getMilliseconds().toString().padStart(3, '0')
    return `${hh}:${mm}:${ss}.${ms}`
  }
  return `${hh}:${mm}:${ss}`
}

/**
 * Format timestamp as friendly localized date & time string.
 */
export function formatLocalDateTime(ts, options) {
  const d = parseDate(ts)
  if (Number.isNaN(d.getTime())) return '—'
  return d.toLocaleString([], options)
}

/**
 * Get short timezone name, resolving "Asia/Calcutta" or "Asia/Kolkata" to "IST".
 */
export function getLocalTimezoneLabel() {
  try {
    const tz = Intl.DateTimeFormat().resolvedOptions().timeZone
    if (tz === 'Asia/Calcutta' || tz === 'Asia/Kolkata') return 'IST'
    const parts = new Intl.DateTimeFormat('en-US', { timeZoneName: 'short' }).formatToParts(new Date())
    const name = parts.find((p) => p.type === 'timeZoneName')?.value
    if (name) return name
  } catch {
    // fallback
  }
  return 'IST'
}
