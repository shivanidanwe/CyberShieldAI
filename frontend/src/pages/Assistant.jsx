import { useCallback, useEffect, useRef, useState } from 'react'
import { api } from '../lib/api'
import { ErrorNotice, Panel, Spinner } from '../components/shared'

const QUICK_PROMPTS = [
  'What is the current threat level?',
  'Explain recent alerts',
  'Recommend next steps',
  'What traffic patterns look suspicious?',
  'How to mitigate detected attacks?',
]

export default function Assistant() {
  const [messages, setMessages] = useState([
    { role: 'assistant', content: 'Hello — I\'m your CyberShield AI security assistant. Ask me about threats, alerts, or recommended actions.', ts: new Date().toISOString() },
  ])
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const bottomRef = useRef(null)
  const inputRef = useRef(null)

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  const send = useCallback(async (text) => {
    if (!text.trim() || loading) return
    const userMsg = { role: 'user', content: text.trim(), ts: new Date().toISOString() }
    setMessages((prev) => [...prev, userMsg])
    setInput('')
    setLoading(true)
    setError('')
    try {
      const recentContext = messages.slice(-10).map((m) => `${m.role}: ${m.content}`).join('\n')
      const result = await api.post('/ai/assistant', {
        message: text.trim(),
        context: recentContext || undefined,
      })
      const assistantMsg = {
        role: 'assistant',
        content: result.reply || result.response || 'I could not generate a response.',
        ts: new Date().toISOString(),
      }
      setMessages((prev) => [...prev, assistantMsg])
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
      inputRef.current?.focus()
    }
  }, [loading, messages])

  const handleSubmit = (e) => {
    e.preventDefault()
    send(input)
  }

  return (
    <div className="page-stack">
      {error && <ErrorNotice message={error} />}

      <Panel kicker="AI Copilot" title="Security Assistant">
        <div className="assistant-chat">
          <div className="chat-messages">
            {messages.map((msg, i) => (
              <div key={i} className={`chat-bubble ${msg.role}`}>
                <div className="bubble-meta">
                  <strong>{msg.role === 'assistant' ? 'AI Assistant' : 'You'}</strong>
                  <span className="muted">
                    {new Date(msg.ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                  </span>
                </div>
                <div className="bubble-content">
                  {msg.content.split('\n').map((line, j) => (
                    <p key={j}>{line}</p>
                  ))}
                </div>
              </div>
            ))}
            {loading && (
              <div className="chat-bubble assistant">
                <div className="bubble-meta"><strong>AI Assistant</strong></div>
                <div className="bubble-content"><Spinner label="Thinking…" inline /></div>
              </div>
            )}
            <div ref={bottomRef} />
          </div>

          <div className="quick-prompts">
            {QUICK_PROMPTS.map((prompt) => (
              <button
                key={prompt}
                type="button"
                className="ghost-button sm"
                onClick={() => send(prompt)}
                disabled={loading}
              >
                {prompt}
              </button>
            ))}
          </div>

          <form className="chat-input-bar" onSubmit={handleSubmit}>
            <input
              ref={inputRef}
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="Ask about threats, alerts, or recommendations…"
              aria-label="Chat message input"
              disabled={loading}
            />
            <button type="submit" className="primary-btn" disabled={loading || !input.trim()}>
              Send
            </button>
          </form>
        </div>
      </Panel>
    </div>
  )
}
