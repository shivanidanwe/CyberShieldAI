import { navigate } from '../lib/router'
import { useAuth } from '../context/AuthContext'

const NAV_ITEMS = [
  { path: '/overview', label: 'Overview', icon: '◉' },
  { path: '/network', label: 'Network', icon: '⇄' },
  { path: '/alerts', label: 'Alerts', icon: '⚠' },
  { path: '/analytics', label: 'Analytics', icon: '◔' },
  { path: '/assistant', label: 'AI Assistant', icon: '✦' },
  { path: '/settings', label: 'Settings', icon: '⚙' },
]

function threatPostureLabel() {
  // Kept lightweight; the Overview page computes posture from live data.
  return 'Elevated'
}

export default function Sidebar({ path, onNavigate }) {
  const { user, logout } = useAuth()

  const select = (target) => {
    if (onNavigate) onNavigate(target)
    navigate(target)
  }

  return (
    <aside className="sidebar">
      <div className="brand-block">
        <div className="brand-mark">C</div>
        <div>
          <p className="eyebrow">SOC Platform</p>
          <h2>CyberShield AI</h2>
        </div>
      </div>

      <nav className="nav-menu" aria-label="Sidebar navigation">
        {NAV_ITEMS.map((item) => (
          <button
            key={item.path}
            type="button"
            className={`nav-item ${path === item.path ? 'active' : ''}`}
            aria-current={path === item.path ? 'page' : undefined}
            onClick={() => select(item.path)}
          >
            <span className="nav-icon" aria-hidden="true">{item.icon}</span>
            {item.label}
          </button>
        ))}
      </nav>

      <div className="sidebar-card">
        <p className="card-label">Threat posture</p>
        <strong>{threatPostureLabel()}</strong>
        <span>Live posture is computed from current alert activity.</span>
      </div>

      <div className="sidebar-footer">
        {user && (
          <div className="user-block">
            <div className="user-avatar" aria-hidden="true">
              {(user.username || 'U').slice(0, 1).toUpperCase()}
            </div>
            <div className="user-meta">
              <strong>{user.username || 'Analyst'}</strong>
              <span>{user.role || 'analyst'}</span>
            </div>
            <button type="button" className="logout-btn" onClick={logout} title="Sign out" aria-label="Sign out">
              ⎋
            </button>
          </div>
        )}
      </div>
    </aside>
  )
}