import { getLocalTimezoneLabel } from '../lib/dateUtils'

const PAGE_META = {
  '/overview': { eyebrow: 'Security Operations Center', title: 'Threat Intelligence Overview' },
  '/network': { eyebrow: 'Traffic Analysis', title: 'Network Activity' },
  '/alerts': { eyebrow: 'Incident Response', title: 'Security Alerts' },
  '/analytics': { eyebrow: 'AI Insights', title: 'Anomaly Analytics' },
  '/assistant': { eyebrow: 'AI Copilot', title: 'Security Assistant' },
  '/settings': { eyebrow: 'Platform', title: 'Settings' },
}

export default function Topbar({ path, captureStatus, onCaptureToggle, busy }) {
  const meta = PAGE_META[path] || PAGE_META['/overview']
  const tzLabel = getLocalTimezoneLabel()

  return (
    <header className="topbar">
      <div>
        <p className="eyebrow">{meta.eyebrow}</p>
        <h1>{meta.title}</h1>
      </div>
      <div className="topbar-actions">
        <span className="tz-pill" title={`System Timezone: ${tzLabel} (UTC+5:30)`}>
          🕒 {tzLabel}
        </span>
        {onCaptureToggle && captureStatus && (
          <>
            <button
              type="button"
              className={`capture-toggle ${captureStatus.enabled ? 'active' : ''}`}
              onClick={onCaptureToggle}
              disabled={busy}
              title={captureStatus.enabled ? 'Click to stop live packet capture' : 'Click to start live packet capture on active interface'}
            >
              {captureStatus.enabled ? 'Stop Capture' : 'Start Capture'}
            </button>
            <span className={`status-dot ${captureStatus.enabled ? 'live' : 'idle'}`} aria-hidden="true" />
            <span
              className={`status-pill ${captureStatus.enabled ? 'live' : 'idle'}`}
              title={captureStatus.interface ? `Capturing on interface: ${captureStatus.interface}` : ''}
            >
              {captureStatus.enabled ? 'Live Monitoring' : 'Monitoring Paused'}
            </span>
          </>
        )}
      </div>
    </header>
  )
}