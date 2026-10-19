import { useEffect, useRef, useState } from 'react'
import { api } from './api'

export default function ConversationExportDialog({ conversation, onClose, onComplete }) {
  const [password, setPassword] = useState('')
  const [code, setCode] = useState('')
  const [needsCode, setNeedsCode] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const dialogRef = useRef(null)
  const passwordRef = useRef(null)
  const closeRef = useRef(onClose)

  useEffect(() => {
    closeRef.current = onClose
  }, [onClose])

  useEffect(() => {
    passwordRef.current?.focus()
    function handleKeys(event) {
      if (event.key === 'Escape' && !busy) {
        event.preventDefault()
        closeRef.current()
        return
      }
      if (event.key !== 'Tab') return
      const focusable = [...dialogRef.current.querySelectorAll(
        'button:not(:disabled), input:not(:disabled)',
      )].filter((element) => element.getClientRects().length > 0)
      const first = focusable[0]
      const last = focusable.at(-1)
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault()
        last?.focus()
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault()
        first?.focus()
      }
    }
    document.addEventListener('keydown', handleKeys)
    return () => document.removeEventListener('keydown', handleKeys)
  }, [busy])

  async function submit(event) {
    event.preventDefault()
    setBusy(true)
    setError(null)
    try {
      await api.reauthenticate(password, code.trim() || undefined)
      const link = document.createElement('a')
      link.href = api.exportConversationUrl(conversation.id)
      link.download = ''
      document.body.appendChild(link)
      link.click()
      link.remove()
      onComplete()
    } catch (requestError) {
      if (requestError.body?.two_factor_required) setNeedsCode(true)
      setError(requestError.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="document-preview-backdrop conversation-export-backdrop">
      <section
        ref={dialogRef}
        className="document-preview conversation-export-dialog"
        role="dialog"
        aria-modal="true"
        aria-busy={busy}
        aria-labelledby="conversation-export-title"
        aria-describedby="conversation-export-summary"
      >
        <header>
          <div>
            <h2 id="conversation-export-title">Export conversation</h2>
            <p title={conversation.title}>{conversation.title || 'Untitled conversation'}</p>
          </div>
        </header>
        <form className="document-preview-body" onSubmit={submit}>
          <p id="conversation-export-summary" className="conversation-export-summary">
            Confirm your identity before downloading this conversation as Markdown.
          </p>
          {error && <div className="login-error" role="alert">{error}</div>}
          <label className="settings-field">
            <span>Current password</span>
            <input
              ref={passwordRef}
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              disabled={busy}
              required
            />
          </label>
          {needsCode && <label className="settings-field">
            <span>2FA or recovery code</span>
            <input
              type="text"
              autoComplete="one-time-code"
              value={code}
              onChange={(event) => setCode(event.target.value)}
              disabled={busy}
              required
            />
          </label>}
          <div className="conversation-export-actions">
            <button type="button" onClick={onClose} disabled={busy}>Cancel</button>
            <button
              type="submit"
              className="primary"
              disabled={busy || !password || (needsCode && !code.trim())}
            >
              {busy ? 'Verifying…' : 'Verify and download'}
            </button>
          </div>
        </form>
      </section>
    </div>
  )
}
