import { useCallback, useEffect, useRef, useState } from 'react'
import { api } from '../lib/api'
import { EmptyState, ErrorNotice, Panel, Spinner, notify } from '../components/shared'

const BAR_COLORS = {
  CRITICAL: '#a855f7',
  HIGH: '#f87171',
  MEDIUM: '#fbbf24',
  LOW: '#34d399',
}

const TOP_IP_COLORS = ['#60a5fa', '#34d399', '#fbbf24', '#f87171', '#a855f7']

function HorizontalBarChart({ data, maxVal, colors }) {
  const total = maxVal || Math.max(...data.map((d) => d.value), 1)
  return (
    <div className="hbar-chart">
      {data.map((entry, i) => (
        <div key={entry.label} className="hbar-row">
          <span className="hbar-label">{entry.label}</span>
          <div className="hbar-track" role="presentation">
            <div
              className="hbar-fill"
              style={{
                width: `${Math.min((entry.value / total) * 100, 100)}%`,
                background: colors[i % colors.length],
              }}
            />
          </div>
          <span className="hbar-value">{entry.value}</span>
        </div>
      ))}
    </div>
  )
}

export default function Analytics() {
  const [dashboard, setDashboard] = useState(null)
  const [insights, setInsights] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [scanning, setScanning] = useState(false)
  const [threshold, setThreshold] = useState(0.65)
  const loadedRef = useRef(false)

  const fetchData = useCallback(async () => {
    setLoading(!loadedRef.current)
    try {
      const [dash, ins] = await Promise.all([
        api.get('/dashboard'),
        api.get('/ai/insights'),
      ])
      setDashboard(dash)
      setInsights(ins)
      setError('')
      loadedRef.current = true
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchData()
  }, [fetchData])

  const runScan = async () => {
    setScanning(true)
    try {
      const result = await api.post('/ai/anomaly-scan', {
        threshold,
        limit: 200,
        create_alerts: true,
      })
      notify(
        `Scan complete — ${result.anomalies_found} anomalies found, ${result.alerts_created} alerts created.`,
        result.anomalies_found > 0 ? 'warning' : 'success',
      )
      fetchData()
    } catch (err) {
      notify(`Scan failed: ${err.message}`, 'error')
    } finally {
      setScanning(false)
    }
  }

  const severityData = dashboard
    ? Object.entries(dashboard.severity_breakdown ?? {})
        .map(([label, value]) => ({ label, value: Number(value) }))
        .sort((a, b) => {
          const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
          return order.indexOf(a.label) - order.indexOf(b.label)
        })
    : []

  const topIpData = dashboard
    ? (dashboard.top_source_ips ?? []).map((item) => ({
        label: item.source_ip,
        value: item.count,
      }))
    : []

  const dailyData = dashboard
    ? (dashboard.alerts_per_day ?? []).map((item) => ({
        label: new Date(item.date).toLocaleDateString([], { weekday: 'short' }).slice(0, 3),
        value: Number(item.count),
      }))
    : []

  return (
    <div className="page-stack">
      {error && <ErrorNotice message={error} onRetry={fetchData} />}

      <section className="insight-grid">
        <Panel kicker="ML Detection" title="Anomaly Scanner" actions={
          <span className="mini-label">Isolation Forest</span>
        }>
          {loading ? (
            <Spinner label="Loading analytics…" />
          ) : (
            <div className="scanner-controls">
              <div className="field-group">
                <label htmlFor="threshold">Anomaly threshold</label>
                <input
                  id="threshold"
                  type="range"
                  min="0.3"
                  max="0.95"
                  step="0.05"
                  value={threshold}
                  onChange={(e) => setThreshold(Number(e.target.value))}
                  aria-label="Anomaly detection threshold"
                />
                <span className="mono">{threshold.toFixed(2)}</span>
              </div>
              <button type="button" className="primary-btn" onClick={runScan} disabled={scanning}>
                {scanning ? 'Scanning…' : 'Run Anomaly Scan'}
              </button>
              <p className="muted" style={{ marginTop: 8 }}>
                Scans stored packets and flags statistical anomalies. Higher thresholds = fewer but more suspicious alerts.
              </p>
            </div>
          )}
        </Panel>

        <Panel kicker="AI Insights" title="Threat Summary">
          {loading ? (
            <Spinner label="Loading insights…" />
          ) : insights?.insights?.length ? (
            <div className="insight-list">
              {insights.insights.map((item, i) => {
                const val = String(item.value || '')
                const isHigh = val.toUpperCase().includes('CRITICAL') || val.toUpperCase().includes('HIGH')
                const isMed = val.toUpperCase().includes('ELEVATED') || val.toUpperCase().includes('MEDIUM')
                return (
                  <div key={i} className="insight-row">
                    <span className="muted">{item.label}</span>
                    <strong className={isHigh ? 'danger-text' : isMed ? 'warning-text' : ''}>
                      {item.value}
                    </strong>
                  </div>
                )
              })}
            </div>
          ) : (
            <EmptyState title="No insights available" hint="Generate traffic data to populate insights." />
          )}
        </Panel>
      </section>

      <section className="insight-grid">
        <Panel kicker="Severity" title="Alert Distribution">
          {loading ? <Spinner label="Loading…" /> : severityData.length === 0
            ? <EmptyState title="No severity data" />
            : <HorizontalBarChart data={severityData} colors={Object.values(BAR_COLORS)} />
          }
        </Panel>

        <Panel kicker="Sources" title="Top Offending IPs">
          {loading ? <Spinner label="Loading…" /> : topIpData.length === 0
            ? <EmptyState title="No source IP data" />
            : <HorizontalBarChart data={topIpData} colors={TOP_IP_COLORS} />
          }
        </Panel>

        <Panel kicker="Trend" title="Alerts per Day">
          {loading ? <Spinner label="Loading…" /> : dailyData.length === 0
            ? <EmptyState title="No daily trend data" />
            : (
              <div className="sparkline-grid">
                {dailyData.map((d, i) => (
                  <div key={i} className="sparkline-cell">
                    <span className="sparkline-label">{d.label}</span>
                    <strong>{d.value}</strong>
                  </div>
                ))}
              </div>
            )
          }
        </Panel>
      </section>
    </div>
  )
}
