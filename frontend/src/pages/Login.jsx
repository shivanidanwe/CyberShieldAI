import { useState } from 'react'
import { useAuth } from '../context/AuthContext'
import { notify } from '../components/shared'

export default function Login() {
  const { login } = useAuth()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const handleSubmit = async (e) => {
    e.preventDefault()
    if (!username.trim() || !password.trim()) {
      setError('Please enter both username and password.')
      return
    }
    setLoading(true)
    setError('')
    try {
      await login(username.trim(), password)
      notify(`Welcome back, ${username.trim()}!`, 'success')
    } catch (err) {
      setError(err.message || 'Invalid credentials.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="login-page">
      <div className="login-card">
        <div className="brand-block centered">
          <div className="brand-mark lg">C</div>
          <div>
            <p className="eyebrow">SOC Platform</p>
            <h1>CyberShield AI</h1>
            <p className="muted">Sign in to access the Security Operations Center</p>
          </div>
        </div>

        <form onSubmit={handleSubmit} className="login-form">
          {error && <div className="error-banner">{error}</div>}
          <div className="field-group">
            <label htmlFor="username">Username</label>
            <input
              id="username"
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="analyst"
              autoComplete="username"
              autoFocus
            />
          </div>
          <div className="field-group">
            <label htmlFor="password">Password</label>
            <input
              id="password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••"
              autoComplete="current-password"
            />
          </div>
          <button type="submit" className="primary-btn full-width" disabled={loading}>
            {loading ? 'Signing in…' : 'Sign In'}
          </button>
          <p className="muted" style={{ textAlign: 'center', marginTop: 12 }}>
            Demo credentials: <strong>analyst / password</strong>
          </p>
        </form>
      </div>
    </div>
  )
}
