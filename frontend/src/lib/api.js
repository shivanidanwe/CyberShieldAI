// Small typed fetch wrapper around the CyberShield backend API.
// The Vite dev server proxies /api -> http://127.0.0.1:8000.

const BASE = '/api'

function buildQuery(params) {
  if (!params) return ''
  const parts = []
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === '') continue
    parts.push(`${encodeURIComponent(key)}=${encodeURIComponent(value)}`)
  }
  return parts.length ? `?${parts.join('&')}` : ''
}

async function request(path, { method = 'GET', body, params } = {}) {
  const url = BASE + path + buildQuery(params)
  const options = { method, headers: {} }
  if (body !== undefined) {
    options.headers['Content-Type'] = 'application/json'
    options.body = JSON.stringify(body)
  }

  const response = await fetch(url, options)
  if (!response.ok) {
    let detail = `Request failed (${response.status})`
    try {
      const data = await response.json()
      if (data && typeof data.detail === 'string') detail = data.detail
    } catch {
      /* keep generic detail */
    }
    const error = new Error(detail)
    error.status = response.status
    throw error
  }

  const contentType = response.headers.get('content-type') || ''
  if (contentType.includes('text/csv')) return response.text()
  return response.json()
}

export const api = {
  get: (path, params) => request(path, { params }),
  post: (path, body) => request(path, { method: 'POST', body }),
  delete: (path, body) => request(path, { method: 'DELETE', body }),
}

/** Download a CSV endpoint as a real file (works through the Vite proxy too). */
export async function downloadCsv(path, filename) {
  const text = await request(path, { params: { limit: 1000 } })
  const blob = new Blob([text], { type: 'text/csv;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  document.body.appendChild(link)
  link.click()
  link.remove()
  URL.revokeObjectURL(url)
}

export { BASE }