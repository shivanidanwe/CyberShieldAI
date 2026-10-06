import { useEffect, useState } from 'react'

// --------------------------------------------------------------------------
// Small shared UI primitives used across all pages.
// --------------------------------------------------------------------------

export function Spinner({ label = 'Loading…', inline = false }) {
  if (inline) return <span className="spinner" role="status" aria-label={label} />
  return (
    <div className="empty-state" role="status">
      <span className="spinner" aria-hidden="true" />
      <p>{label}</p>
    </div>
  )
}

export function EmptyState({ title, hint = 'Nothing here yet — new activity will show up automatically.' }) {
  return (
    <div className="empty-state">
      <div className="empty-icon" aria-hidden="true">◌</div>
      <p className="empty-title">{title}</p>
      <p className="muted empty-hint">{hint}</p>
    </div>
  )
}

export function ErrorNotice({ message, onRetry }) {
  return (
    <div className="error-banner" role="alert">
      <span className="error-banner-text">{message}</span>
      {onRetry && (
        <button type="button" className="error-retry" onClick={onRetry}>
          Retry
        </button>
      )}
    </div>
  )
}

export function Panel({ kicker, title, actions, children, className = '' }) {
  return (
    <section className={`panel ${className}`.trim()}>
      {(kicker || title || actions) && (
        <div className={actions ? 'panel-header row-header' : 'panel-header'}>
          <div>
            {kicker && <p className="panel-kicker">{kicker}</p>}
            {title && <h2>{title}</h2>}
          </div>
          {actions && <div className="panel-actions">{actions}</div>}
        </div>
      )}
      {children}
    </section>
  )
}

const SEVERITY_CLASS = { high: 'severity-high', medium: 'severity-medium', low: 'severity-low', critical: 'severity-critical' }

export function SeverityChip({ severity }) {
  const key = String(severity || 'medium').toLowerCase()
  const className = SEVERITY_CLASS[key] || 'severity-medium'
  return <span className={`chip ${className}`}>{severity || 'MEDIUM'}</span>
}

export function RefreshToggle({ enabled, onChange }) {
  return (
    <label className="switch-row">
      <input type="checkbox" checked={enabled} onChange={(event) => onChange(event.target.checked)} />
      <span className="switch" aria-hidden="true" />
      <span>Live refresh</span>
    </label>
  )
}

// --------------------------------------------------------------------------
// Toast notifications
// --------------------------------------------------------------------------

let toastListener = null

export function notify(message, type = 'info') {
  if (toastListener) toastListener({ id: Date.now() + Math.random(), message, type })
}

export function ToastHost() {
  const [toasts, setToasts] = useState([])

  useEffect(() => {
    toastListener = (toast) => {
      setToasts((current) => [...current, toast])
      setTimeout(() => {
        setToasts((current) => current.filter((item) => item.id !== toast.id))
      }, 4200)
    }
    return () => {
      toastListener = null
    }
  }, [])

  if (!toasts.length) return null
  return (
    <div className="toast-host" aria-live="polite">
      {toasts.map((toast) => (
        <div key={toast.id} className={`toast toast-${toast.type}`}>
          {toast.message}
        </div>
      ))}
    </div>
  )
}

// --------------------------------------------------------------------------
// Modal
// --------------------------------------------------------------------------

export function Modal({ title, onClose, children, wide = false }) {
  useEffect(() => {
    const onKey = (event) => {
      if (event.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  return (
    <div className="modal-backdrop" onClick={onClose} role="presentation">
      <div
        className={`modal ${wide ? 'modal-wide' : ''}`}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        onClick={(event) => event.stopPropagation()}
      >
        <div className="modal-head">
          <h2>{title}</h2>
          <button type="button" className="modal-close" onClick={onClose} aria-label="Close">
            ✕
          </button>
        </div>
        {children}
      </div>
    </div>
  )
}

// --------------------------------------------------------------------------
// Pagination
// --------------------------------------------------------------------------

export function Pagination({ page, pageSize, total, onPage }) {
  const pages = Math.max(1, Math.ceil(total / pageSize))
  if (pages <= 1) return null
  return (
    <div className="pagination">
      <button type="button" className="ghost-button" disabled={page <= 1} onClick={() => onPage(page - 1)}>
        ‹ Prev
      </button>
      <span className="pagination-info">
        Page {page} of {pages} · {total.toLocaleString()} records
      </span>
      <button type="button" className="ghost-button" disabled={page >= pages} onClick={() => onPage(page + 1)}>
        Next ›
      </button>
    </div>
  )
}