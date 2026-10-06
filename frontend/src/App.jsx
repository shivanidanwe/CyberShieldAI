import { useCallback, useEffect, useState } from 'react'
import { AuthProvider, useAuth } from './context/AuthContext'
import { useHashRoute } from './lib/router'
import { api } from './lib/api'
import Sidebar from './components/Sidebar'
import Topbar from './components/Topbar'
import { ToastHost, notify } from './components/shared'
import Login from './pages/Login'
import Overview from './pages/Overview'
import Network from './pages/Network'
import Alerts from './pages/Alerts'
import Analytics from './pages/Analytics'
import Assistant from './pages/Assistant'
import Settings from './pages/Settings'

const PAGES = {
  '/overview': Overview,
  '/network': Network,
  '/alerts': Alerts,
  '/analytics': Analytics,
  '/assistant': Assistant,
  '/settings': Settings,
}

function AppShell() {
  const { authenticated } = useAuth()
  const path = useHashRoute()
  const [captureStatus, setCaptureStatus] = useState({ enabled: false })
  const [captureBusy, setCaptureBusy] = useState(false)
  const [sidebarOpen, setSidebarOpen] = useState(false)

  const fetchCaptureStatus = useCallback(async () => {
    try {
      const status = await api.get('/packets/capture/status')
      setCaptureStatus(status)
    } catch {
      // Capture endpoint may be unavailable; silently ignore.
    }
  }, [])

  useEffect(() => {
    fetchCaptureStatus()
    const interval = setInterval(fetchCaptureStatus, 6000)
    return () => clearInterval(interval)
  }, [fetchCaptureStatus])

  const handleCaptureToggle = async () => {
    setCaptureBusy(true)
    try {
      const next = !captureStatus.enabled
      const res = await api.post('/packets/capture/toggle', { enabled: next })
      setCaptureStatus(res || { enabled: next })
      if (next) {
        notify(`Live capture started on ${res?.interface || 'active interface'}.`, 'success')
      } else {
        notify('Live capture stopped.', 'info')
      }
    } catch (err) {
      notify(`Capture toggle failed: ${err.message}`, 'error')
    } finally {
      setCaptureBusy(false)
    }
  }

  if (!authenticated) return <Login />

  const Page = PAGES[path] || Overview

  return (
    <div className={`app-layout ${sidebarOpen ? 'sidebar-open' : ''}`}>
      <button
        type="button"
        className="sidebar-hamburger"
        onClick={() => setSidebarOpen((prev) => !prev)}
        aria-label="Toggle navigation menu"
      >
        ☰
      </button>

      <Sidebar path={path} onNavigate={() => setSidebarOpen(false)} />

      {sidebarOpen && (
        <div className="sidebar-backdrop" onClick={() => setSidebarOpen(false)} aria-hidden="true" />
      )}

      <div className="main-area">
        <Topbar
          path={path}
          captureStatus={captureStatus}
          onCaptureToggle={handleCaptureToggle}
          busy={captureBusy}
        />
        <main className="page-content">
          <Page captureStatus={captureStatus} onCaptureToggle={handleCaptureToggle} />
        </main>
      </div>
    </div>
  )
}

export default function App() {
  return (
    <AuthProvider>
      <AppShell />
      <ToastHost />
    </AuthProvider>
  )
}
