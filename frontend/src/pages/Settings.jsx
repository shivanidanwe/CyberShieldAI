import { useState } from 'react'
import { api } from '../lib/api'
import { Panel, notify } from '../components/shared'
import { useAuth } from '../context/AuthContext'

export default function Settings() {
  const { user } = useAuth()
  const [seedLoading, setSeedLoading] = useState(false)
  const [clearLoading, setClearLoading] = useState(false)

  const handleSeed = async () => {
    setSeedLoading(true)
    try {
      const result = await api.post('/seed', { force: false })
      notify(result.message || 'Seed data loaded.', 'success')
    } catch (err) {
      notify(`Seed failed: ${err.message}`, 'error')
    } finally {
      setSeedLoading(false)
    }
  }

  const handleClear = async () => {
    if (!window.confirm('Clear ALL packets and alerts? This cannot be undone.')) return
    setClearLoading(true)
    try {
      const result = await api.post('/seed', { force: true, clear: true })
      notify(result.message || 'Database cleared.', 'success')
    } catch (err) {
      notify(`Clear failed: ${err.message}`, 'error')
    } finally {
      setClearLoading(false)
    }
  }

  return (
    <div className="page-stack">
      <section className="settings-grid">
        <Panel kicker="Account" title="Current User">
          <div className="settings-profile">
            <div className="user-avatar lg" aria-hidden="true">
              {(user?.username || 'U').slice(0, 1).toUpperCase()}
            </div>
            <div>
              <strong>{user?.username || 'Analyst'}</strong>
              <span className="muted">{user?.role || 'analyst'}</span>
            </div>
          </div>
        </Panel>

        <Panel kicker="Data Management" title="Seed & Reset">
          <div className="settings-actions">
            <div>
              <p>Load realistic demo traffic and alerts into the database.</p>
              <button type="button" className="primary-btn" onClick={handleSeed} disabled={seedLoading}>
                {seedLoading ? 'Seeding…' : 'Seed Demo Data'}
              </button>
            </div>
            <hr />
            <div>
              <p className="danger-text">Permanently remove all packets and alerts from the database.</p>
              <button type="button" className="primary-btn danger" onClick={handleClear} disabled={clearLoading}>
                {clearLoading ? 'Clearing…' : 'Clear All Data'}
              </button>
            </div>
          </div>
        </Panel>

        <Panel kicker="System" title="Platform Info">
          <div className="settings-info">
            <div className="info-row">
              <span className="muted">Platform</span>
              <strong>CyberShield AI v1.0</strong>
            </div>
            <div className="info-row">
              <span className="muted">Backend</span>
              <strong>FastAPI + SQLAlchemy</strong>
            </div>
            <div className="info-row">
              <span className="muted">Frontend</span>
              <strong>React + Vite</strong>
            </div>
            <div className="info-row">
              <span className="muted">AI Engine</span>
              <strong>Pure Python Isolation Forest (offline)</strong>
            </div>
            <div className="info-row">
              <span className="muted">Capture</span>
              <strong>Scapy packet sniffer (admin required)</strong>
            </div>
          </div>
        </Panel>

        <Panel kicker="About" title="CyberShield AI Mini-SOC">
          <p className="muted">
            CyberShield AI is a self-contained Security Operations Center demo platform for educational and authorized security testing purposes.
            It includes real-time packet capture, rule-based and ML-based anomaly detection, an AI security assistant,
            and comprehensive alert management — all running locally with no external dependencies required.
          </p>
        </Panel>
      </section>
    </div>
  )
}
