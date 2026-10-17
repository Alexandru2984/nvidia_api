import { useEffect, useState } from 'react'
import { api } from './api'


function normalizeAttachmentPage(page) {
  if (Array.isArray(page)) return { results: page, nextCursor: null }
  return {
    results: Array.isArray(page?.results) ? page.results : [],
    nextCursor: typeof page?.next_cursor === 'string' ? page.next_cursor : null,
  }
}


function formatBytes(bytes) {
  const value = Number(bytes) || 0
  if (value < 1024) return `${value} B`
  if (value < 1048576) return `${(value / 1024).toFixed(1)} KB`
  return `${(value / 1048576).toFixed(1)} MB`
}


function TwoFactorPanel() {
  const [status, setStatus] = useState(null)
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)

  // enroll wizard state
  const [enrollData, setEnrollData] = useState(null)  // { secret, provisioning_uri, qr_data_url }
  const [enrollPassword, setEnrollPassword] = useState('')
  const [enrollCode, setEnrollCode] = useState('')
  const [recoveryCodes, setRecoveryCodes] = useState(null)

  // disable state
  const [showDisable, setShowDisable] = useState(false)
  const [disablePassword, setDisablePassword] = useState('')
  const [disableCode, setDisableCode] = useState('')

  // regen state
  const [showRegen, setShowRegen] = useState(false)
  const [regenPassword, setRegenPassword] = useState('')
  const [regenCode, setRegenCode] = useState('')

  async function refresh() {
    try {
      const s = await api.twoFactorStatus()
      setStatus(s)
    } catch (e) { setError(e.message) }
  }
  useEffect(() => {
    let cancelled = false
    api.twoFactorStatus().then((value) => { if (!cancelled) setStatus(value) })
      .catch((e) => { if (!cancelled) setError(e.message) })
    return () => { cancelled = true }
  }, [])

  async function startEnroll() {
    setError(null); setBusy(true)
    try {
      setEnrollData(await api.twoFactorEnroll(enrollPassword))
      setRecoveryCodes(null)
      setEnrollCode('')
    } catch (e) { setError(e.message) }
    finally { setEnrollPassword(''); setBusy(false) }
  }
  async function confirmEnroll() {
    setError(null); setBusy(true)
    try {
      const r = await api.twoFactorVerifyEnroll(enrollCode.trim())
      setRecoveryCodes(r.recovery_codes)
      setEnrollData(null)
      await refresh()
    } catch (e) { setError(e.message) }
    finally { setEnrollCode(''); setBusy(false) }
  }
  async function doDisable() {
    setError(null); setBusy(true)
    try {
      await api.twoFactorDisable(disablePassword, disableCode.trim())
      setShowDisable(false)
      setDisablePassword(''); setDisableCode('')
      await refresh()
    } catch (e) { setError(e.message) }
    finally { setDisablePassword(''); setDisableCode(''); setBusy(false) }
  }
  async function doRegenRecovery() {
    setError(null); setBusy(true)
    try {
      const r = await api.twoFactorRegenRecovery(regenPassword, regenCode.trim())
      setRecoveryCodes(r.recovery_codes)
      setShowRegen(false)
      await refresh()
    } catch (e) { setError(e.message) }
    finally { setRegenPassword(''); setRegenCode(''); setBusy(false) }
  }

  if (!status) return <div role="status">{error || 'Loading 2FA status…'}</div>

  return (
    <section className="settings-section">
      <h2>Two-factor authentication</h2>
      <p className="muted">
        Adds a 6-digit code from an authenticator app (Google Authenticator, Authy, 1Password) on top of your password.
      </p>
      {error && <div className="login-error">{error}</div>}

      {!status.enabled && !enrollData && (
        <div className="enroll-card">
          <p>Confirm your current password before creating a new authenticator secret.</p>
          <label className="settings-field">
            <span>Current password</span>
            <input
              type="password" autoComplete="current-password"
              value={enrollPassword} onChange={(e) => setEnrollPassword(e.target.value)}
            />
          </label>
          <button className="primary" onClick={startEnroll} disabled={busy || !enrollPassword}>
            {busy ? 'Checking…' : 'Enable 2FA'}
          </button>
        </div>
      )}

      {!status.enabled && enrollData && (
        <div className="enroll-card">
          <p>1. Scan this QR with your authenticator app, or enter the secret manually.</p>
          <img className="two-factor-qr" src={enrollData.qr_data_url} alt="2FA QR" />
          <pre className="secret-box" style={{ userSelect: 'all' }}>{enrollData.secret}</pre>
          <p>2. Enter the 6-digit code your app shows now:</p>
          <input
            type="text" inputMode="numeric" pattern="[0-9]*" maxLength={6}
            value={enrollCode} onChange={(e) => setEnrollCode(e.target.value)}
            placeholder="123456"
          />
          <div className="settings-actions">
            <button className="primary" onClick={confirmEnroll} disabled={busy || enrollCode.length !== 6}>
              Confirm and enable
            </button>
            <button className="link" onClick={() => {
              setEnrollData(null); setEnrollPassword(''); setEnrollCode(''); setError(null)
            }}>Cancel</button>
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
          <div className="settings-actions">
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
          <div className="settings-actions">
            <button className="primary danger" onClick={doDisable} disabled={busy || !disablePassword || !disableCode}>
              Disable 2FA
            </button>
            <button className="link" onClick={() => {
              setShowDisable(false); setDisablePassword(''); setDisableCode(''); setError(null)
            }}>Cancel</button>
          </div>
        </div>
      )}

      {showRegen && (
        <div className="enroll-card">
          <p>Confirm your password and current 2FA code (or an unused recovery code). This invalidates the old set.</p>
          <label className="settings-field">
            <span>Current password</span>
            <input
              type="password" autoComplete="current-password"
              value={regenPassword} onChange={(e) => setRegenPassword(e.target.value)}
            />
          </label>
          <label className="settings-field">
            <span>2FA or recovery code</span>
            <input
              type="text" autoComplete="one-time-code" maxLength={17}
              value={regenCode} onChange={(e) => setRegenCode(e.target.value)}
            />
          </label>
          <div className="settings-actions">
            <button className="primary" onClick={doRegenRecovery} disabled={busy || !regenPassword || !regenCode}>
              Regenerate
            </button>
            <button className="link" onClick={() => {
              setShowRegen(false); setRegenPassword(''); setRegenCode(''); setError(null)
            }}>Cancel</button>
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
  const [pendingAction, setPendingAction] = useState(null)
  const [reauthPassword, setReauthPassword] = useState('')
  const [reauthCode, setReauthCode] = useState('')
  const [reauthNeedsCode, setReauthNeedsCode] = useState(false)

  async function refresh() {
    try { setSessions(await api.listSessions()) } catch (e) { setError(e.message) }
  }
  useEffect(() => {
    let cancelled = false
    api.listSessions().then((value) => { if (!cancelled) setSessions(value) })
      .catch((e) => { if (!cancelled) setError(e.message) })
    return () => { cancelled = true }
  }, [])

  async function performRevocation(action) {
    try {
      if (action.type === 'one') await api.revokeSession(action.key)
      else await api.revokeOtherSessions()
      await refresh()
      return true
    } catch (e) {
      if (e.body?.reauthentication_required) {
        setPendingAction(action)
        setReauthNeedsCode(Boolean(e.body?.two_factor_required))
        setError('Confirm your identity before changing active sessions.')
        return false
      }
      setError(e.message)
      return false
    }
  }
  async function revokeOne(key) {
    if (!confirm('Sign this session out?')) return
    setBusy(true)
    setError(null)
    try { await performRevocation({ type: 'one', key }) }
    finally { setBusy(false) }
  }
  async function revokeOthers() {
    if (!confirm('Sign out everywhere except here?')) return
    setBusy(true)
    setError(null)
    try { await performRevocation({ type: 'others' }) }
    finally { setBusy(false) }
  }
  async function reauthenticateAndContinue(e) {
    e.preventDefault()
    if (!pendingAction) return
    setBusy(true); setError(null)
    try {
      await api.reauthenticate(reauthPassword, reauthCode.trim() || undefined)
      const action = pendingAction
      setPendingAction(null); setReauthPassword(''); setReauthCode('')
      setReauthNeedsCode(false)
      await performRevocation(action)
    } catch (err) {
      if (err.body?.two_factor_required) setReauthNeedsCode(true)
      setError(err.message)
    } finally { setBusy(false) }
  }
  function cancelReauthentication() {
    setPendingAction(null); setReauthPassword(''); setReauthCode('')
    setReauthNeedsCode(false); setError(null)
  }

  if (!sessions) return <div role="status">{error || 'Loading sessions…'}</div>

  return (
    <section className="settings-section">
      <h2>Active sessions</h2>
      <p className="muted">
        Each browser gets a bounded session with a fixed maximum lifetime. Older sessions are removed automatically; revoke any you don't recognize.
      </p>
      {error && <div className="login-error">{error}</div>}
      {pendingAction && (
        <form className="enroll-card" onSubmit={reauthenticateAndContinue}>
          <p>For your security, this action needs a recent sign-in confirmation.</p>
          <label className="settings-field">
            <span>Current password</span>
            <input type="password" autoComplete="current-password"
              value={reauthPassword} onChange={(e) => setReauthPassword(e.target.value)} required />
          </label>
          {reauthNeedsCode && <label className="settings-field">
            <span>2FA or recovery code</span>
            <input type="text" autoComplete="one-time-code" maxLength={17}
              value={reauthCode} onChange={(e) => setReauthCode(e.target.value)} required />
          </label>}
          <div className="settings-actions">
            <button className="primary" type="submit"
              disabled={busy || !reauthPassword || (reauthNeedsCode && !reauthCode)}>
              {busy ? 'Confirming…' : 'Confirm and continue'}
            </button>
            <button className="link" type="button" onClick={cancelReauthentication}>Cancel</button>
          </div>
        </form>
      )}
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
  const [code, setCode] = useState('')
  const [needsCode, setNeedsCode] = useState(false)
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
      const r = await api.changePassword(current, next, code.trim() || undefined)
      setInfo(`Password changed. ${r.sessions_revoked} other session(s) signed out.`)
      setCurrent(''); setNext(''); setConfirm(''); setCode(''); setNeedsCode(false)
    } catch (e2) {
      if (e2.body?.two_factor_required) setNeedsCode(true)
      setError(e2.message)
    }
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
        {needsCode && <input type="text" placeholder="2FA code or recovery code"
          autoComplete="one-time-code" maxLength={17}
          value={code} onChange={(e) => setCode(e.target.value)} required />}
        <button className="primary" type="submit"
          disabled={busy || !current || !next || !confirm || (needsCode && !code)}>
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


function StoragePanel() {
  const [usage, setUsage] = useState(null)
  const [retention, setRetention] = useState(null)
  const [files, setFiles] = useState([])
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)
  const [nextCursor, setNextCursor] = useState(null)
  const [loadingMore, setLoadingMore] = useState(false)
  const [retentionBusy, setRetentionBusy] = useState(false)
  const [exportOpen, setExportOpen] = useState(false)
  const [exportPassword, setExportPassword] = useState('')
  const [exportCode, setExportCode] = useState('')
  const [exportNeedsCode, setExportNeedsCode] = useState(false)
  const [exportBusy, setExportBusy] = useState(false)
  const [exportError, setExportError] = useState(null)
  useEffect(() => {
    let cancelled = false
    Promise.all([
      api.accountUsage(), api.listAttachments(), api.chatRetention(),
    ]).then(([stats, attachments, retentionPolicy]) => {
      if (cancelled) return
      const page = normalizeAttachmentPage(attachments)
      setUsage(stats); setFiles(page.results); setNextCursor(page.nextCursor)
      setRetention(retentionPolicy)
    }).catch((e) => { if (!cancelled) setError(e.message) })
    return () => { cancelled = true }
  }, [])

  async function remove(file) {
    if (!confirm(`Delete ${file.original_name}? This cannot be undone.`)) return
    setBusy(true); setError(null)
    try {
      await api.deleteAttachment(file.id)
      setFiles((items) => items.filter((item) => item.id !== file.id))
      setUsage(await api.accountUsage())
    } catch (e) { setError(e.message) }
    finally { setBusy(false) }
  }

  async function loadMore() {
    if (!nextCursor || loadingMore) return
    setLoadingMore(true); setError(null)
    try {
      const page = normalizeAttachmentPage(await api.listAttachments(undefined, nextCursor))
      setFiles((current) => {
        const byId = new Map(current.map((file) => [file.id, file]))
        for (const file of page.results) byId.set(file.id, file)
        return [...byId.values()]
      })
      setNextCursor(page.nextCursor)
    } catch (e) { setError(e.message) }
    finally { setLoadingMore(false) }
  }

  async function changeRetention(event) {
    const archivedDays = Number(event.target.value)
    if (archivedDays > 0 && !confirm(
      `Permanently delete archived conversations after ${archivedDays} days of inactivity? `
      + 'Messages and linked files will also be deleted. There is no undo.',
    )) {
      event.target.value = String(retention.archived_days)
      return
    }
    setRetentionBusy(true); setError(null)
    try {
      setRetention(await api.updateChatRetention(archivedDays))
    } catch (e) { setError(e.message) }
    finally { setRetentionBusy(false) }
  }

  async function downloadAccountExport(event) {
    event.preventDefault()
    setExportBusy(true); setExportError(null)
    try {
      await api.reauthenticate(exportPassword, exportCode.trim() || undefined)
      const link = document.createElement('a')
      link.href = api.accountExportUrl()
      link.download = ''
      document.body.appendChild(link)
      link.click()
      link.remove()
      setExportOpen(false); setExportCode(''); setExportNeedsCode(false)
    } catch (e) {
      if (e.body?.two_factor_required) setExportNeedsCode(true)
      setExportError(e.message)
    } finally {
      setExportPassword('')
      setExportBusy(false)
    }
  }

  return <section className="settings-section">
    <h2>Storage & files</h2>
    {error && <p className="login-error" role="alert">{error}</p>}
    {usage ? <>
      <p className="muted">{(usage.storage_bytes / 1048576).toFixed(1)} MB of {Math.round(usage.storage_limit_bytes / 1048576)} MB used</p>
      <progress aria-label="Storage used" value={usage.storage_bytes} max={usage.storage_limit_bytes} />
      <div className="usage-stats">
        <span>{usage.conversations} conversations</span>
        <span>{usage.messages} messages</span>
        <span>{usage.attachments} files</span>
      </div>
      {usage.conversation_limit && usage.message_limit
        && usage.message_limit_per_conversation && <div className="object-usage-card">
        <h3>Saved chat data</h3>
        <label>
          <span>Conversations</span>
          <strong>{usage.conversations.toLocaleString()} / {usage.conversation_limit.toLocaleString()}</strong>
          <progress aria-label="Conversation storage used" value={usage.conversations}
            max={Math.max(1, usage.conversation_limit)} />
        </label>
        <label>
          <span>Messages</span>
          <strong>{usage.messages.toLocaleString()} / {usage.message_limit.toLocaleString()}</strong>
          <progress aria-label="Message storage used" value={usage.messages}
            max={Math.max(1, usage.message_limit)} />
          <small className="muted">
            Up to {usage.message_limit_per_conversation.toLocaleString()} messages per conversation.
          </small>
        </label>
        {usage.message_bytes_limit > 0 && <label>
          <span>Saved message text</span>
          <strong>{formatBytes(usage.message_bytes)} / {formatBytes(usage.message_bytes_limit)}</strong>
          <progress aria-label="Saved message text used" value={usage.message_bytes}
            max={Math.max(1, usage.message_bytes_limit)} />
          <small className="muted">
            Up to {formatBytes(usage.message_bytes_limit_per_conversation)} per conversation.
          </small>
        </label>}
      </div>}
      {retention && <div className="retention-card">
        <h3>Archived chat retention</h3>
        <p className="muted">
          Active conversations are never deleted automatically. This policy applies only to
          archived conversations that have not changed during the selected period.
        </p>
        <label className="settings-field">
          <span>Automatic deletion</span>
          <select value={retention.archived_days} onChange={changeRetention}
            disabled={retentionBusy} aria-label="Archived chat retention">
            {retention.choices.map((choice) => (
              <option key={choice.days} value={choice.days}>{choice.label}</option>
            ))}
          </select>
        </label>
        {retention.archived_days > 0 && <p className="retention-warning" role="status">
          Archived messages and linked files are permanently deleted after
          {' '}{retention.archived_days} inactive days. Restore a chat before then to keep it.
        </p>}
      </div>}
      <div className="export-card">
        <h3>Export your data</h3>
        <p className="muted">
          Download a private JSON file containing your account profile, conversations,
          messages, settings, session metadata, AI usage, and an attachment manifest.
          File contents and internal security values are never included.
        </p>
        {!exportOpen ? <button className="link" onClick={() => {
          setExportOpen(true); setExportError(null)
        }}>Prepare account export…</button> : <form onSubmit={downloadAccountExport}>
          {exportError && <p className="login-error" role="alert">{exportError}</p>}
          <label className="settings-field">
            <span>Current password</span>
            <input type="password" autoComplete="current-password"
              value={exportPassword} onChange={(event) => setExportPassword(event.target.value)}
              required />
          </label>
          {exportNeedsCode && <label className="settings-field">
            <span>2FA or recovery code</span>
            <input type="text" autoComplete="one-time-code" maxLength={17}
              value={exportCode} onChange={(event) => setExportCode(event.target.value)}
              required />
          </label>}
          <div className="export-actions">
            <button className="primary" type="submit"
              disabled={exportBusy || !exportPassword || (exportNeedsCode && !exportCode)}>
              {exportBusy ? 'Preparing…' : 'Verify and download'}
            </button>
            <button className="link" type="button" onClick={() => {
              setExportOpen(false); setExportPassword(''); setExportCode('')
              setExportNeedsCode(false); setExportError(null)
            }}>Cancel</button>
          </div>
        </form>}
      </div>
      {usage.ai_today && <div className="ai-usage-card">
        <h3>Today's AI usage</h3>
        {!usage.ai_today.enabled && <p className="login-error">AI generation is temporarily disabled.</p>}
        <label>
          <span>Chat requests</span>
          <strong>{usage.ai_today.chat_requests} / {usage.ai_today.chat_limit}</strong>
          <progress aria-label="Daily chat requests used" value={usage.ai_today.chat_requests}
            max={Math.max(1, usage.ai_today.chat_limit)} />
        </label>
        <label>
          <span>Generated images</span>
          <strong>{usage.ai_today.image_requests} / {usage.ai_today.image_limit}</strong>
          <progress aria-label="Daily generated images used" value={usage.ai_today.image_requests}
            max={Math.max(1, usage.ai_today.image_limit)} />
        </label>
        <label>
          <span>Chat tokens</span>
          <strong>{(usage.ai_today.token_budget_used || 0).toLocaleString()} / {(usage.ai_today.token_limit || 0).toLocaleString()}</strong>
          <progress aria-label="Daily chat token budget used" value={usage.ai_today.token_budget_used || 0}
            max={Math.max(1, usage.ai_today.token_limit || 0)} />
          {usage.ai_today.reserved_tokens > 0 && <small className="muted">
            Includes {usage.ai_today.reserved_tokens.toLocaleString()} tokens reserved for active or unmetered requests.
          </small>}
        </label>
        <p className="muted">Resets at {new Date(usage.ai_today.resets_at).toLocaleString()} (UTC budget window).</p>
      </div>}
      <div className="file-library">
        {files.length === 0 && <p className="muted">No files uploaded yet.</p>}
        {files.map((file) => <div className="library-row" key={file.id}>
          <div><a href={file.url} download>{file.original_name}</a><small>{Math.max(1, Math.round(file.size / 1024))} KB · {file.deletable ? 'Unattached' : 'Linked to a conversation'}</small></div>
          {file.deletable && <button className="link danger" disabled={busy} onClick={() => remove(file)} aria-label={`Delete ${file.original_name}`}>Delete</button>}
        </div>)}
        {nextCursor && (
          <button className="library-load-more" onClick={loadMore} disabled={loadingMore}>
            {loadingMore ? 'Loading…' : 'Load more files'}
          </button>
        )}
      </div>
    </> : !error && <p role="status">Loading storage…</p>}
  </section>
}

export default function Settings({ onClose, onLoggedOut, theme, onThemeChange }) {
  return (
    <div className="settings-wrap">
      <header className="settings-header">
        <h1>Settings</h1>
        <button className="icon" onClick={onClose} title="Close">×</button>
      </header>
      <div className="settings-body">
        <section className="settings-section">
          <h2>Appearance</h2>
          <label className="theme-field"><span>Color theme</span>
            <select value={theme} onChange={(e) => onThemeChange(e.target.value)}>
              <option value="dark">Dark</option><option value="light">Light</option>
            </select>
          </label>
        </section>
        <StoragePanel />
        <PasswordPanel />
        <TwoFactorPanel />
        <SessionsPanel />
        <DangerPanel onLoggedOut={onLoggedOut} />
      </div>
    </div>
  )
}
