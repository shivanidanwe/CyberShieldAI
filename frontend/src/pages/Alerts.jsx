import { useCallback, useEffect, useRef, useState } from 'react'
import { api, downloadCsv } from '../lib/api'
import { EmptyState, ErrorNotice, Panel, SeverityChip, Spinner, notify } from '../components/shared'
import { formatLocalDateTime, getLocalTimezoneLabel } from '../lib/dateUtils'

const SEVERITY_OPTIONS = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

export default function Alerts() {
  const [alerts, setAlerts] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [severity, setSeverity] = useState('ALL')
  const [search, setSearch] = useState('')
  const [searchInput, setSearchInput] = useState('')
  const loadedRef = useRef(false)

  const fetchAlerts = useCallback(async () => {
    setLoading(!loadedRef.current)
    try {
      const params = {}
      if (severity !== 'ALL') params.severity = severity
      if (search.trim()) params.q = search.trim()
      const data = await api.get('/alerts', params)
      setAlerts(data)
      setError('')
      loadedRef.current = true
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }, [severity, search])

  useEffect(() => {
    fetchAlerts()
  }, [fetchAlerts])

  // Debounced search input.
  useEffect(() => {
    const timer = setTimeout(() => setSearch(searchInput), 350)
    return () => clearTimeout(timer)
  }, [searchInput])

  const handleDeleteAlert = async (id) => {
    try {
      await api.delete(`/alerts/${id}`)
      setAlerts((prev) => prev.filter((a) => a.id !== id))
      notify('Alert deleted.', 'success')
    } catch (err) {
      notify(`Delete failed: ${err.message}`, 'error')
    }
  }

  const handleClearAll = async () => {
    if (!window.confirm('Delete ALL alerts? This cannot be undone.')) return
    try {
      await api.delete('/alerts')
      setAlerts([])
      notify('All alerts cleared.', 'success')
    } catch (err) {
      notify(`Clear failed: ${err.message}`, 'error')
    }
  }

  const handleExport = async () => {
    try {
      await downloadCsv('/reports/csv/alerts', `alerts_${new Date().toISOString().slice(0, 10)}.csv`)
      notify('Alerts exported as CSV.', 'success')
    } catch (err) {
      notify(`Export failed: ${err.message}`, 'error')
    }
  }

  const handleExplain = async (alert) => {
    try {
      const result = await api.post('/ai/explain', {
        attack_type: alert.attack_type,
        severity: alert.severity,
        source_ip: alert.source_ip,
        destination_ip: alert.destination_ip,
        description: alert.description || '',
      })
      notify(result.explanation || 'Explanation generated — check AI Assistant page.', 'info')
    } catch (err) {
      notify(`Explain failed: ${err.message}`, 'error')
    }
  }

  return (
    <div className="page-stack">
      {error && <ErrorNotice message={error} onRetry={fetchAlerts} />}

      <Panel
        kicker="Incident Response"
        title="Security Alerts"
        actions={
          <>
            <input
              className="filter-select"
              type="search"
              placeholder="Search alerts…"
              value={searchInput}
              onChange={(event) => setSearchInput(event.target.value)}
              aria-label="Search alerts"
            />
            <select
              className="filter-select"
              value={severity}
              onChange={(event) => setSeverity(event.target.value)}
              aria-label="Filter by severity"
            >
              {SEVERITY_OPTIONS.map((option) => (
                <option key={option} value={option}>{option === 'ALL' ? 'All severities' : option}</option>
              ))}
            </select>
            <button type="button" className="ghost-button" onClick={handleExport}>Export CSV</button>
            <button type="button" className="ghost-button" onClick={handleClearAll}>Clear All</button>
          </>
        }
      >
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th scope="col">Type</th>
                <th scope="col">Severity</th>
                <th scope="col">Source</th>
                <th scope="col">Destination</th>
                <th scope="col">Description</th>
                <th scope="col">Time ({getLocalTimezoneLabel()})</th>
                <th scope="col">Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading && alerts.length === 0 ? (
                <tr>
                  <td colSpan="7">
                    <Spinner label="Loading alerts…" inline />
                  </td>
                </tr>
              ) : alerts.length === 0 ? (
                <tr>
                  <td colSpan="7">
                    <EmptyState title="No alerts found" hint="Adjust filters or generate traffic to trigger detections." />
                  </td>
                </tr>
              ) : (
                alerts.map((alert) => (
                  <tr key={alert.id}>
                    <td>{alert.attack_type}</td>
                    <td><SeverityChip severity={alert.severity} /></td>
                    <td className="mono">{alert.source_ip}</td>
                    <td className="mono">{alert.destination_ip}</td>
                    <td className="muted">{alert.description || '—'}</td>
                    <td className="muted">
                      {formatLocalDateTime(alert.timestamp, {
                        month: 'short',
                        day: 'numeric',
                        hour: '2-digit',
                        minute: '2-digit',
                      })}
                    </td>
                    <td>
                      <div className="action-btns">
                        <button type="button" className="ghost-button sm" onClick={() => handleExplain(alert)} title="AI explain">
                          ✦ Explain
                        </button>
                        <button type="button" className="ghost-button sm danger" onClick={() => handleDeleteAlert(alert.id)} title="Delete alert">
                          ✕
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        <div className="pagination-bar">
          <span className="muted">{alerts.length} alert{alerts.length !== 1 ? 's' : ''}</span>
        </div>
      </Panel>
    </div>
  )
}
