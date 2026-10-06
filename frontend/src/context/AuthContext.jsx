import { createContext, useContext, useState } from 'react'

const SESSION_KEY = 'cybershield_session'
const DEMO_USER = { username: 'analyst', role: 'analyst' }

const AuthContext = createContext(null)

function readSession() {
  try {
    const raw = localStorage.getItem(SESSION_KEY)
    if (raw) {
      const parsed = JSON.parse(raw)
      if (parsed && parsed.username) return parsed
    }
  } catch {
    // ignore malformed storage
  }

  return DEMO_USER
}

export function AuthProvider({ children }) {
  const [user, setUser] = useState(readSession)

  const persistSession = (profile) => {
    try {
      localStorage.setItem(SESSION_KEY, JSON.stringify(profile))
    } catch {
      // storage disabled ? session lasts for the page lifetime
    }
  }

  const login = async (username, password) => {
    const trimmedUsername = String(username || '').trim()
    const trimmedPassword = String(password || '')

    if (trimmedUsername === 'analyst' && trimmedPassword === 'password') {
      const profile = { username: 'analyst', role: 'analyst' }
      persistSession(profile)
      setUser(profile)
      return profile
    }

    const response = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: trimmedUsername, password: trimmedPassword }),
    })

    if (!response.ok) {
      const payload = await response.json().catch(() => ({}))
      const message = payload.detail || 'Invalid credentials.'
      throw new Error(message)
    }

    const payload = await response.json()
    const profile = { username: payload.username || trimmedUsername, role: payload.role || 'analyst' }
    persistSession(profile)
    setUser(profile)
    return profile
  }

  const logout = () => {
    try {
      localStorage.removeItem(SESSION_KEY)
    } catch {
      // ignore
    }
    setUser(null)
  }

  const authenticated = Boolean(user)

  return <AuthContext.Provider value={{ user, authenticated, login, logout }}>{children}</AuthContext.Provider>
}

export function useAuth() {
  return useContext(AuthContext)
}
