import { useCallback, useEffect, useMemo, useState } from 'react'
import { api, downloadCsv } from '../lib/api'
import { EmptyState, ErrorNotice, Panel, SeverityChip, Spinner, notify } from '../components/shared'
import { formatLocalDateTime, getLocalTimezoneLabel, parseDate } from '../lib/dateUtils'

const emptyForm = {
  source_ip: '10.0.0.20',
  destination_ip: '10.0.0.10',
  protocol: 'TCP',
  source_port: '50000',
  destination_port: '23',
  packet_length: '320',
}

const SEVERITIES = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
const DONUT_COLORS = {
  LOW: '#34d399',
  MEDIUM: '#fbbf24',
  HIGH: '#f87171',
  CRITICAL: '#a855f7',
}

function buildDonutGradient(breakdown) {
  const total = Object.values(breakdown).reduce((sum, value) => sum + Number(value || 0), 0)
  if (!total) return '#22304a'
  let cursor = 0
  const stops = []
  for (const severity of SEVERITIES) {
    const count = Number(breakdown[severity] || 0)
    if (!count) continue
    const start = (cursor / total) * 100
    cursor += count
    const end = (cursor / total) * 100
    const color = DONUT_COLORS[severity]
    stops.push(`${color} ${start}% ${end}%`)
  }
  return stops.length ? `conic-gradient(${stops.join(', ')})` : '#22304a'
}

function TrendChart({ series }) {
  const points = series && series.length ? series : Array.from({ length: 7 }, () => ({ count: 0 }))
  const values = points.map((point) => Number(point.count) || 0)
  const max = Math.max(...values, 1)
  const width = 320
  const height = 150
  const pad = 8

  const coords = values.map((value, index) => {
    const x = pad + (index * (width - pad * 2)) / Math.max(values.length - 1, 1)
    const y = height - pad - (value / max) * (height - pad * 2)
    return { x, y }
  })

  const linePath = coords.map((point, index) => `${index === 0 ? 'M' : 'L'} ${point.x.toFixed(1)} ${point.y.toFixed(1)}`).join(' ')
  const areaPath = `${linePath} L ${width - pad} ${height} L ${pad} ${height} Z`

  const labels = points.map((point) => {
    const date = new Date(point.date)
    return Number.isNaN(date.getTime())
      ? '—'
      : date.toLocaleDateString([], { weekday: 'short' }).slice(0, 3)
  })

  return (
    <div>
      <svg className="line-chart" viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none" role="img" aria-label="Threat trend chart">
        <defs>
          <linearGradient id="chartLine" x1="0" x2="1">
            <stop offset="0%" stopColor="#60a5fa" />
            <stop offset="100%" stopColor="#34d399" />
          </linearGradient>
        </defs>
        <path d={areaPath} fill="rgba(96, 165, 250, 0.14)" />
        <path d={linePath} fill="none" stroke="url(#chartLine)" strokeWidth="3" strokeLinecap="round" />
      </svg>
      <div className="chart-labels">
        {labels.map((label, index) => (
          <span key={index}>{label}</span>
        ))}
      </div>
    </div>
  )
}

function StatCard({ label, value, badge, badgeClass = '', accent }) {
  return (
    <article className={`stat-card accent-${accent}`}>
      <div className="stat-head">
        <span>{label}</span>
        {badge && <span className={`stat-badge ${badgeClass}`}>{badge}</span>}
      </div>
      <strong>{value}</strong>
    </article>
  )
}

function PacketForm({ onSubmit, submitting }) {
  const [form, setForm] = useState(emptyForm)

  const handleInputChange = (event) => {
    const { name, value } = event.target
    setForm((current) => ({ ...current, [name]: value }))
  }

  const handleSubmit = async (event) => {
    event.preventDefault()
    await onSubmit({
      source_ip: form.source_ip,
      destination_ip: form.destination_ip,
      protocol: form.protocol,
      source_port: form.source_port ? Number(form.source_port) : null,
      destination_port: form.destination_port ? Number(form.destination_port) : null,
      packet_length: Number(form.packet_length) || 0,
      timestamp: new Date().toISOString(),
    })
    setForm(emptyForm)
  }

  return (
    <form className="packet-form" onSubmit={handleSubmit}>
      <div className="field-group">
        <label htmlFor="source_ip">Source IP</label>
        <input id="source_ip" name="source_ip" value={form.source_ip} onChange={handleInputChange} />
      </div>
      <div className="field-group">
        <label htmlFor="destination_ip">Destination IP</label>
        <input id="destination_ip" name="destination_ip" value={form.destination_ip} onChange={handleInputChange} />
      </div>
      <div className="field-row">
        <div className="field-group">
          <label htmlFor="protocol">Protocol</label>
          <select id="protocol" name="protocol" value={form.protocol} onChange={handleInputChange}>
            <option value="TCP">TCP</option>
            <option value="UDP">UDP</option>
            <option value="ICMP">ICMP</option>
          </select>
        </div>
        <div className="field-group">
          <label htmlFor="packet_length">Packet Length</label>
          <input id="packet_length" name="packet_length" value={form.packet_length} onChange={handleInputChange} />
        </div>
      </div>
      <div className="field-row">
        <div className="field-group">
          <label htmlFor="source_port">Source Port</label>
          <input id="source_port" name="source_port" value={form.source_port} onChange={handleInputChange} />
        </div>
        <div className="field-group">
          <label htmlFor="destination_port">Destination Port</label>
          <input id="destination_port" name="destination_port" value={form.destination_port} onChange={handleInputChange} />
        </div>
      </div>
      <button type="submit" className="primary-btn" disabled={submitting}>
        {submitting ? 'Submitting…' : 'Submit Packet'}
      </button>
    </form>
  )
}

export default function Overview() {
  const [dashboard, setDashboard] = useState({
    total_packets: 0,
    total_alerts: 0,
    severity_breakdown: {},
    protocol_breakdown: {},
    recent_alerts: [],
    packets_per_day: [],
    alerts_per_day: [],
    top_source_ips: [],
  })
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [submitting, setSubmitting] = useState(false)

  const fetchDashboard = useCallback(async () => {
    try {
      const data = await api.get('/dashboard')
      setDashboard(data)
      setError('')
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchDashboard()
    const interval = setInterval(fetchDashboard, 5000)
    return () => clearInterval(interval)
  }, [fetchDashboard])

  const severityEntries = useMemo(
    () => Object.entries(dashboard.severity_breakdown ?? {}).sort((a, b) => SEVERITIES.indexOf(a[0]) - SEVERITIES.indexOf(b[0])),
    [dashboard.severity_breakdown],
  )
  const protocolEntries = useMemo(() => Object.entries(dashboard.protocol_breakdown ?? {}), [dashboard.protocol_breakdown])
  const highAlertCount = Number(dashboard.severity_breakdown?.HIGH ?? 0) + Number(dashboard.severity_breakdown?.CRITICAL ?? 0)
  const last24Alerts = useMemo(() => {
    const dayAgo = Date.now() - 24 * 60 * 60 * 1000
    return dashboard.recent_alerts.filter((alert) => parseDate(alert.timestamp).getTime() >= dayAgo).length
  }, [dashboard.recent_alerts])

  const handleSubmit = async (payload) => {
    setSubmitting(true)
    setError('')
    try {
      const created = await api.post('/packets', payload)
      notify(
        created.destination_port === 23 ? 'Packet submitted — Telnet alert triggered.' : 'Packet submitted successfully.',
        'success',
      )
      await fetchDashboard()
    } catch (err) {
      setError(err.message)
    } finally {
      setSubmitting(false)
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

  return (
    <>
      {error && <ErrorNotice message={error} onRetry={fetchDashboard} />}

      <section className="stats-grid">
        <StatCard
          label="Total Packets"
          value={loading ? '—' : dashboard.total_packets}
          badge="Today"
          accent="blue"
        />
        <StatCard
          label="Total Alerts"
          value={loading ? '—' : dashboard.total_alerts}
          badge={last24Alerts ? `+${last24Alerts} / 24h` : 'Last 24h'}
          badgeClass="warning"
          accent="red"
        />
        <StatCard
          label="High Severity"
          value={loading ? '—' : highAlertCount}
          badge={highAlertCount ? 'Critical' : 'None'}
          badgeClass={highAlertCount ? 'warning' : ''}
          accent="orange"
        />
        <StatCard
          label="Protocols"
          value={loading ? '—' : protocolEntries.length}
          badge="Healthy"
          badgeClass="success"
          accent="green"
        />
      </section>

      <section className="insight-grid">
        <Panel kicker="Threat trend" title="Attack Activity" actions={<span className="mini-label">Last 7 days</span>}>
          {loading ? <Spinner label="Loading trend…" /> : <TrendChart series={dashboard.packets_per_day ?? dashboard.alerts_per_day} />}
        </Panel>

        <Panel kicker="Severity mix" title="Risk Composition">
          <div className="donut-layout">
            <div
              className="donut-chart"
              style={{ background: buildDonutGradient(dashboard.severity_breakdown ?? {}) }}
              role="img"
              aria-label="Alert severity distribution"
            >
              <div className="donut-center">
                <strong>{dashboard.total_alerts || 0}</strong>
                <span>Alerts</span>
              </div>
            </div>
            <ul className="donut-legend">
              {SEVERITIES.map((severity) => (
                <li key={severity}>
                  <span className={`dot ${DONUT_COLORS[severity] ? '' : ''}`} style={{ background: DONUT_COLORS[severity] }} />
                  {severity} · <strong>{Number(dashboard.severity_breakdown?.[severity] ?? 0)}</strong>
                </li>
              ))}
            </ul>
          </div>
        </Panel>
      </section>

      <main className="content-grid">
        <Panel kicker="Risk Breakdown" title="Alert Summary">
          {loading ? (
            <Spinner label="Loading…" />
          ) : severityEntries.length === 0 ? (
            <EmptyState title="No alerts recorded yet" hint="Submit a packet or start capture to see severity data." />
          ) : (
            <div className="summary-list">
              {severityEntries.map(([severity, count]) => (
                <div key={severity} className="summary-row">
                  <div className="summary-label-row">
                    <span>{severity}</span>
                    <span>{count}</span>
                  </div>
                  <div className="bar-track" role="presentation">
                    <div
                      className={`bar-fill ${severity.toLowerCase()}`}
                      style={{ width: `${Math.min((count / Math.max(dashboard.total_alerts, 1)) * 100, 100)}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>
          )}
        </Panel>

        <Panel kicker="Traffic mix" title="Protocol Distribution">
          {loading ? (
            <Spinner label="Loading…" />
          ) : protocolEntries.length === 0 ? (
            <EmptyState title="No packet data yet" hint="Traffic will appear here as packets are captured or submitted." />
          ) : (
            <div className="protocol-list">
              {protocolEntries.map(([protocol, count]) => (
                <div key={protocol} className="protocol-row">
                  <span>{protocol}</span>
                  <div className="protocol-meter" role="presentation">
                    <div
                      className="protocol-fill"
                      style={{ width: `${Math.min((count / Math.max(dashboard.total_packets, 1)) * 100, 100)}%` }}
                    />
                  </div>
                  <strong>{count}</strong>
                </div>
              ))}
            </div>
          )}
        </Panel>

        <section className="panel wide-panel">
          <div className="panel-header row-header">
            <div>
              <p className="panel-kicker">Live activity</p>
              <h2>Recent Alerts</h2>
            </div>
            <button type="button" className="ghost-button" onClick={handleExport}>
              Export CSV
            </button>
          </div>

          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th scope="col">Type</th>
                  <th scope="col">Severity</th>
                  <th scope="col">Source</th>
                  <th scope="col">Destination</th>
                  <th scope="col">Time ({getLocalTimezoneLabel()})</th>
                </tr>
              </thead>
              <tbody>
                {loading ? (
                  <tr>
                    <td colSpan="5" className="muted">Loading alerts…</td>
                  </tr>
                ) : dashboard.recent_alerts.length === 0 ? (
                  <tr>
                    <td colSpan="5" className="muted">No recent alerts.</td>
                  </tr>
                ) : (
                  dashboard.recent_alerts.map((alert) => (
                    <tr key={alert.id}>
                      <td>{alert.attack_type}</td>
                      <td>
                        <SeverityChip severity={alert.severity} />
                      </td>
                      <td>{alert.source_ip}</td>
                      <td>{alert.destination_ip}</td>
                      <td>
                        {formatLocalDateTime(alert.timestamp, { hour: '2-digit', minute: '2-digit' })}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </section>

        <section className="panel form-panel">
          <div className="panel-header">
            <div>
              <p className="panel-kicker">Testing</p>
              <h2>Simulate Packet</h2>
            </div>
          </div>

          <PacketForm onSubmit={handleSubmit} submitting={submitting} />
        </section>
      </main>
    </>
  )
}