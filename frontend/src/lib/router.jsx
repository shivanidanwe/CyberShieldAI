// Minimal dependency-free hash router.
// Routes live in the URL fragment: #/overview, #/network, #/alerts, ...

import { useEffect, useState } from 'react'

const DEFAULT_ROUTE = '/overview'

function readHash() {
  const hash = window.location.hash.replace(/^#/, '') || DEFAULT_ROUTE
  return hash.startsWith('/') ? hash : `/${hash}`
}

export function useHashRoute() {
  const [route, setRoute] = useState(readHash)

  useEffect(() => {
    const onChange = () => setRoute(readHash())
    window.addEventListener('hashchange', onChange)
    return () => window.removeEventListener('hashchange', onChange)
  }, [])

  return route
}

export function navigate(path) {
  window.location.hash = path
}