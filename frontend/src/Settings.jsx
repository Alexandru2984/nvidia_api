import { useEffect, useState } from 'react'
import { api } from './api'


function TwoFactorPanel() {
  const [status, setStatus] = useState(null)
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)

  // enroll wizard state
  const [enrollData, setEnrollData] = useState(null)  // { secret, provisioning_uri, qr_data_url }
  const [enrollCode, setEnrollCode] = useState('')
  const [recoveryCodes, setRecoveryCodes] = useState(null)

  // disable state
  const [showDisable, setShowDisable] = useState(false)
  const [disablePassword, setDisablePassword] = useState('')
  const [disableCode, setDisableCode] = useState('')

  // regen state
  const [showRegen, setShowRegen] = useState(false)
  const [regenCode, setRegenCode] = useState('')

  async function refresh() {
    try {
      const s = await api.twoFactorStatus()
      setStatus(s)
    } catch (e) { setError(e.message) }
  }
  useEffect(() => { refresh() }, [])

  async function startEnroll() {
    setError(null); setBusy(true)
    try {
      setEnrollData(await api.twoFactorEnroll())
      setRecoveryCodes(null)
      setEnrollCode('')
    } catch (e) { setError(e.message) }
    finally { setBusy(false) }
  }
  async function confirmEnroll() {
    setError(null); setBusy(true)
    try {
      const r = await api.twoFactorVerifyEnroll(enrollCode.trim())
      setRecoveryCodes(r.recovery_codes)
      setEnrollData(null)
      await refresh()
    } catch (e) { setError(e.message) }
    finally { setBusy(false) }
  }
  async function doDisable() {
    setError(null); setBusy(true)
    try {
      await api.twoFactorDisable(disablePassword, disableCode.trim())
      setShowDisable(false)
      setDisablePassword(''); setDisableCode('')
      await refresh()
    } catch (e) { setError(e.message) }
    finally { setBusy(false) }
  }
  async function doRegenRecovery() {
    setError(null); setBusy(true)
    try {
      const r = await api.twoFactorRegenRecovery(regenCode.trim())
      setRecoveryCodes(r.recovery_codes)
      setShowRegen(false); setRegenCode('')
      await refresh()
    } catch (e) { setError(e.message) }
    finally { setBusy(false) }
  }

  if (!status) return <div>Loading 2FA status…</div>

  return (
    <section className="settings-section">
      <h2>Two-factor authentication</h2>
      <p className="muted">
        Adds a 6-digit code from an authenticator app (Google Authenticator, Authy, 1Password) on top of your password.
      </p>
      {error && <div className="login-error">{error}</div>}

      {!status.enabled && !enrollData && (
        <button className="primary" onClick={startEnroll} disabled={busy}>Enable 2FA</button>
      )}

      {!status.enabled && enrollData && (
        <div className="enroll-card">
          <p>1. Scan this QR with your authenticator app, or enter the secret manually.</p>
          <img src={enrollData.qr_data_url} alt="2FA QR" style={{ width: 200, height: 200, background: '#fff', padding: 8, borderRadius: 8 }} />
          <pre className="secret-box" style={{ userSelect: 'all' }}>{enrollData.secret}</pre>
          <p>2. Enter the 6-digit code your app shows now:</p>
          <input
            type="text" inputMode="numeric" pattern="[0-9]*" maxLength={6}
            value={enrollCode} onChange={(e) => setEnrollCode(e.target.value)}
            placeholder="123456"
          />
          <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
            <button className="primary" onClick={confirmEnroll} disabled={busy || enrollCode.length !== 6}>
              Confirm and enable
            </button>
            <button className="link" onClick={() => setEnrollData(null)}>Cancel</button>
          </div>
        </div>
      )}

      {recoveryCodes && (
        <div className="recovery-card">
          <h3>Save your recovery codes</h3>
          <p className="muted">
            Each code works once if you lose your authenticator. Store them somewhere safe — they will not be shown again.
          </p>
          <pre className="recovery-box">{recoveryCodes.join('\n')}</pre>
          <button className="link" onClick={() => setRecoveryCodes(null)}>I've saved them</button>
        </div>
      )}

      {status.enabled && !showDisable && !showRegen && (
        <div>
          <p>2FA is <strong>enabled</strong>. {status.recovery_codes_remaining} recovery code(s) remaining.</p>
          <div style={{ display: 'flex', gap: 8 }}>
            <button className="link" onClick={() => setShowRegen(true)}>Regenerate recovery codes</button>
            <button className="link danger" onClick={() => setShowDisable(true)}>Disable 2FA</button>
          </div>
        </div>
      )}

      {showDisable && (
        <div className="enroll-card">
          <p>Confirm with your password and a current 2FA code (or unused recovery code):</p>
          <input
            type="password" placeholder="Password"
            value={disablePassword} onChange={(e) => setDisablePassword(e.target.value)}
          />
          <input
            type="text" placeholder="2FA code or recovery code"
            value={disableCode} onChange={(e) => setDisableCode(e.target.value)}
            style={{ marginTop: 8 }}
          />
          <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
            <button className="primary danger" onClick={doDisable} disabled={busy || !disablePassword || !disableCode}>
              Disable 2FA
            </button>
            <button className="link" onClick={() => setShowDisable(false)}>Cancel</button>
          </div>
        </div>
      )}

      {showRegen && (
        <div className="enroll-card">
          <p>Enter a current 2FA code to issue 10 fresh recovery codes (this invalidates the old set):</p>
          <input
            type="text" inputMode="numeric" maxLength={6} placeholder="123456"
            value={regenCode} onChange={(e) => setRegenCode(e.target.value)}
          />
          <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
            <button className="primary" onClick={doRegenRecovery} disabled={busy || regenCode.length !== 6}>
              Regenerate
            </button>
            <button className="link" onClick={() => setShowRegen(false)}>Cancel</button>
          </div>
        </div>
      )}
    </section>
  )
}


function SessionsPanel() {
  const [sessions, setSessions] = useState(null)
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)

  async function refresh() {
    try { setSessions(await api.listSessions()) } catch (e) { setError(e.message) }
  }
  useEffect(() => { refresh() }, [])

  async function revokeOne(key) {
    if (!confirm('Sign this session out?')) return
    setBusy(true)
    try { await api.revokeSession(key); await refresh() }
    catch (e) { setError(e.message) }
    finally { setBusy(false) }
  }
  async function revokeOthers() {
    if (!confirm('Sign out everywhere except here?')) return
    setBusy(true)
    try { await api.revokeOtherSessions(); await refresh() }
    catch (e) { setError(e.message) }
    finally { setBusy(false) }
  }

  if (!sessions) return <div>Loading sessions…</div>

  return (
    <section className="settings-section">
      <h2>Active sessions</h2>
      <p className="muted">Each browser you sign in from gets its own session. Revoke any you don't recognize.</p>
      {error && <div className="login-error">{error}</div>}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        {sessions.map((s) => (
          <div key={s.id} className="session-row">
            <div>
              <div><strong>{s.current ? 'This device' : 'Other device'}</strong></div>
              <div className="muted" style={{ fontSize: 12 }}>
                {s.ua ? s.ua.slice(0, 80) : 'Unknown UA'} · IP {s.ip || '—'}
              </div>
              <div className="muted" style={{ fontSize: 12 }}>
                Signed in {s.login_at ? new Date(s.login_at).toLocaleString() : '—'} · expires {new Date(s.expires_at).toLocaleString()}
              </div>
            </div>
            {!s.current && (
              <button className="link danger" onClick={() => revokeOne(s.id)} disabled={busy}>Sign out</button>
            )}
          </div>
        ))}
      </div>
      {sessions.filter((s) => !s.current).length > 0 && (
        <button className="link danger" onClick={revokeOthers} disabled={busy} style={{ marginTop: 12 }}>
          Sign out of all other sessions
        </button>
      )}
    </section>
  )
}


function PasswordPanel() {
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [confirm, setConfirm] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const [info, setInfo] = useState(null)

  async function submit(e) {
    e.preventDefault()
    setError(null); setInfo(null)
    if (next !== confirm) { setError('New passwords do not match.'); return }
    if (next.length < 8) { setError('New password must be at least 8 characters.'); return }
    setBusy(true)
    try {
      const r = await api.changePassword(current, next)
      setInfo(`Password changed. ${r.sessions_revoked} other session(s) signed out.`)
      setCurrent(''); setNext(''); setConfirm('')
    } catch (e2) { setError(e2.message) }
    finally { setBusy(false) }
  }

  return (
    <section className="settings-section">
      <h2>Change password</h2>
      <p className="muted">Changing your password signs out every other device.</p>
      {error && <div className="login-error">{error}</div>}
      {info && <div className="login-info">{info}</div>}
      <form onSubmit={submit} style={{ display: 'flex', flexDirection: 'column', gap: 8, maxWidth: 360 }}>
        <input type="password" placeholder="Current password" autoComplete="current-password"
          value={current} onChange={(e) => setCurrent(e.target.value)} required />
        <input type="password" placeholder="New password (min 8 chars)" autoComplete="new-password"
          value={next} onChange={(e) => setNext(e.target.value)} minLength={8} required />
        <input type="password" placeholder="Repeat new password" autoComplete="new-password"
          value={confirm} onChange={(e) => setConfirm(e.target.value)} minLength={8} required />
        <button className="primary" type="submit" disabled={busy || !current || !next || !confirm}>
          {busy ? 'Changing…' : 'Change password'}
        </button>
      </form>
    </section>
  )
}


function DangerPanel({ onLoggedOut }) {
  const [open, setOpen] = useState(false)
  const [password, setPassword] = useState('')
  const [code, setCode] = useState('')
  const [needsCode, setNeedsCode] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)

  async function doDelete() {
    if (!confirm('This permanently deletes your account, conversations and files. There is no undo. Continue?')) return
    setBusy(true); setError(null)
    try {
      await api.deleteAccount(password, code.trim() || undefined)
      onLoggedOut?.()
    } catch (e) {
      if (e.body?.two_factor_required) setNeedsCode(true)
      setError(e.message)
    } finally { setBusy(false) }
  }

  return (
    <section className="settings-section">
      <h2>Danger zone</h2>
      <p className="muted">Delete your account and every conversation, message and attachment that belongs to it.</p>
      {!open ? (
        <button className="link danger" onClick={() => setOpen(true)}>Delete account…</button>
      ) : (
        <div className="enroll-card">
          {error && <div className="login-error">{error}</div>}
          <input type="password" placeholder="Your password" autoComplete="current-password"
            value={password} onChange={(e) => setPassword(e.target.value)} />
          {needsCode && (
            <input type="text" placeholder="2FA code or recovery code" style={{ marginTop: 8 }}
              value={code} onChange={(e) => setCode(e.target.value)} />
          )}
          <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
            <button className="primary danger" onClick={doDelete} disabled={busy || !password}>
              {busy ? 'Deleting…' : 'Permanently delete account'}
            </button>
            <button className="link" onClick={() => { setOpen(false); setPassword(''); setCode(''); setError(null) }}>Cancel</button>
          </div>
        </div>
      )}
    </section>
  )
}


export default function Settings({ onClose, onLoggedOut }) {
  return (
    <div className="settings-wrap">
      <header className="settings-header">
        <h1>Settings</h1>
        <button className="icon" onClick={onClose} title="Close">×</button>
      </header>
      <div className="settings-body">
        <PasswordPanel />
        <TwoFactorPanel />
        <SessionsPanel />
        <DangerPanel onLoggedOut={onLoggedOut} />
      </div>
    </div>
  )
}
