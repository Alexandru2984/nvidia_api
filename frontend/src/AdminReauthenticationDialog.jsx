import { useEffect, useRef, useState } from 'react'
import { api } from './api'

export default function AdminReauthenticationDialog({ onCancel, onComplete }) {
  const [password, setPassword] = useState('')
  const [code, setCode] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const dialogRef = useRef(null)
  const passwordRef = useRef(null)
  const cancelRef = useRef(onCancel)

  useEffect(() => {
    cancelRef.current = onCancel
  }, [onCancel])

  useEffect(() => {
    passwordRef.current?.focus()
    function handleKeys(event) {
      if (event.key === 'Escape' && !busy) {
        event.preventDefault()
        cancelRef.current()
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
    if (busy) return
    setBusy(true)
    setError(null)
    try {
      await api.reauthenticateAdmin(password, code.trim())
      onComplete()
    } catch (requestError) {
      setError(requestError.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="document-preview-backdrop conversation-export-backdrop">
      <section
        ref={dialogRef}
        className="document-preview conversation-export-dialog admin-reauth-dialog"
        role="dialog"
        aria-modal="true"
        aria-busy={busy}
        aria-labelledby="admin-reauth-title"
        aria-describedby="admin-reauth-summary"
      >
        <header>
          <div>
            <h2 id="admin-reauth-title">Confirm admin access</h2>
            <p>Five-minute elevated session</p>
          </div>
        </header>
        <form className="document-preview-body" onSubmit={submit}>
          <p id="admin-reauth-summary" className="conversation-export-summary">
            Re-enter your password and current authenticator or recovery code before opening Django admin.
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
          <label className="settings-field">
            <span>2FA or recovery code</span>
            <input
              type="text"
              autoComplete="one-time-code"
              spellCheck={false}
              maxLength={64}
              value={code}
              onChange={(event) => setCode(event.target.value)}
              disabled={busy}
              required
            />
          </label>
          <div className="conversation-export-actions">
            <button type="button" onClick={onCancel} disabled={busy}>Cancel</button>
            <button
              type="submit"
              className="primary"
              disabled={busy || !password || !code.trim()}
            >
              {busy ? 'Verifying…' : 'Verify and open admin'}
            </button>
          </div>
        </form>
      </section>
    </div>
  )
}
