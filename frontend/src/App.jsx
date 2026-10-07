import { lazy, Suspense, useEffect, useMemo, useRef, useState } from 'react'
import { api, mediaUrl } from './api'
import DocumentPreview from './DocumentPreview'
import ModelExplorer from './ModelExplorer'
const Settings = lazy(() => import('./Settings'))
const MarkdownBody = lazy(() => import('./MarkdownBody'))

const MAX_FILE_BYTES = 10 * 1024 * 1024
const DOCUMENT_EXTENSIONS = ['pdf', 'txt', 'md', 'docx']
const FALLBACK_IMAGE_EXTENSIONS = ['jpg', 'jpeg', 'png']
const PURPOSE_GROUPS = [
  ['assistant', 'Assistants'],
  ['coding', 'Coding'],
  ['translation', 'Translation'],
  ['safety', 'Safety classifiers'],
  ['specialized', 'Specialized'],
]
const PURPOSE_LABELS = Object.fromEntries(PURPOSE_GROUPS)

function fileExt(name) {
  const i = (name || '').lastIndexOf('.')
  return i >= 0 ? name.slice(i + 1).toLowerCase() : ''
}

function uploadExtension(file) {
  const extension = fileExt(file?.name)
  if (extension) return extension
  return {
    'image/jpeg': 'jpg',
    'image/png': 'png',
    'image/webp': 'webp',
    'application/pdf': 'pdf',
    'text/plain': 'txt',
    'text/markdown': 'md',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document': 'docx',
  }[file?.type] || ''
}

function humanSize(bytes) {
  if (!bytes) return '0 B'
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(0)} KB`
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`
}

function formatContext(tokens) {
  if (!tokens) return 'Context unknown'
  return tokens >= 1000 ? `${Math.round(tokens / 1000)}K context` : `${tokens} context`
}

function formatProbeLatency(performance) {
  const milliseconds = performance?.probe_latency_ms
  if (!Number.isFinite(milliseconds)) return null
  const seconds = milliseconds / 1000
  return `Probe ${seconds < 10 ? seconds.toFixed(1) : Math.round(seconds)}s`
}

function capabilitiesFor(model) {
  if (model?.capabilities) return model.capabilities
  const imageExtensions = model?.vision ? FALLBACK_IMAGE_EXTENSIONS : []
  return {
    input_modalities: ['text', 'document', ...(model?.vision ? ['image'] : [])],
    attachment_extensions: [...DOCUMENT_EXTENSIONS, ...imageExtensions],
    document_extensions: DOCUMENT_EXTENSIONS,
    documents_as_text: true,
    image_mime_types: model?.vision ? ['image/jpeg', 'image/png'] : [],
    max_images: model?.vision ? 1 : 0,
    max_image_bytes: null,
  }
}

function attachmentIsCompatible(attachment, capabilities) {
  if (attachment.kind === 'document') return attachment.has_text !== false
  if (!['image', 'generated_image'].includes(attachment.kind)) return false
  return capabilities.input_modalities.includes('image')
    && capabilities.image_mime_types.includes(attachment.mime_type)
    && (!capabilities.max_image_bytes || attachment.size <= capabilities.max_image_bytes)
}

function sortConversations(items) {
  return [...items].sort((left, right) => (
    Number(Boolean(right.is_pinned)) - Number(Boolean(left.is_pinned))
    || new Date(right.updated_at || 0).getTime() - new Date(left.updated_at || 0).getTime()
  ))
}

function normalizeConversationPage(page, view) {
  if (!Array.isArray(page)) {
    return {
      results: Array.isArray(page?.results) ? page.results : [],
      counts: {
        active: Number(page?.counts?.active) || 0,
        archived: Number(page?.counts?.archived) || 0,
      },
      nextCursor: typeof page?.next_cursor === 'string' ? page.next_cursor : null,
    }
  }
  return {
    results: page,
    counts: {
      active: view === 'active' ? page.length : 0,
      archived: view === 'archived' ? page.length : 0,
    },
    nextCursor: null,
  }
}

function normalizeAttachmentPage(page) {
  if (Array.isArray(page)) return { results: page, count: page.length, nextCursor: null }
  return {
    results: Array.isArray(page?.results) ? page.results : [],
    count: Number(page?.count) || 0,
    nextCursor: typeof page?.next_cursor === 'string' ? page.next_cursor : null,
  }
}

const SUGGESTIONS = [
  'Write a haiku about GPUs warming up at night',
  'Explain mixture-of-experts in three sentences',
  'Refactor this Python loop into a list comprehension: ...',
  "What's the difference between Llama 3.1 70B and 405B?",
]

function CodeScreen({ email, initialCooldown = 60, onVerified, onBack }) {
  const [code, setCode] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const [info, setInfo] = useState(null)
  const [cooldown, setCooldown] = useState(initialCooldown)

  useEffect(() => {
    if (cooldown <= 0) return
    const t = setInterval(() => setCooldown((c) => (c > 0 ? c - 1 : 0)), 1000)
    return () => clearInterval(t)
  }, [cooldown])

  async function submit(e) {
    e.preventDefault()
    if (busy) return
    if (!/^\d{6}$/.test(code)) {
      setError('Enter the 6-digit code from the email.')
      return
    }
    setBusy(true)
    setError(null)
    setInfo(null)
    try {
      const u = await api.verifyCode(email, code)
      onVerified(u)
    } catch (err) {
      setError(err.message || 'Verification failed')
    } finally {
      setBusy(false)
    }
  }

  async function resend() {
    if (cooldown > 0 || busy) return
    setBusy(true)
    setError(null)
    setInfo(null)
    try {
      const r = await api.resend(email)
      setInfo(r.message || 'A new code has been sent.')
      setCooldown(r.resend_available_in || 60)
    } catch (err) {
      if (err.status === 429 && /\d+s/.test(err.message)) {
        const m = err.message.match(/(\d+)s/)
        if (m) setCooldown(parseInt(m[1], 10))
      }
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="login-wrap">
      <form className="login-card" onSubmit={submit}>
        <div className="login-brand">
          <div className="brand-mark">N</div>
          <div>
            <div className="brand-text">Verify your email</div>
            <div className="brand-sub">Enter the 6-digit code</div>
          </div>
        </div>
        <p className="login-hint">
          We sent a code to <strong style={{ color: 'var(--text)' }}>{email}</strong>. The code expires in 30 minutes.
        </p>
        <label>
          <span>Verification code</span>
          <input
            type="text"
            inputMode="numeric"
            pattern="\d{6}"
            maxLength={6}
            className="otp-input"
            value={code}
            onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
            autoFocus
            autoComplete="one-time-code"
            required
          />
        </label>
        {error && <div className="login-error">{error}</div>}
        {info && <div className="login-info">{info}</div>}
        <button type="submit" className="primary login-submit" disabled={busy || code.length !== 6}>
          {busy ? 'Verifying…' : 'Verify and sign in'}
        </button>
        <div className="resend-row">
          <span>Didn't get it?</span>
          <button
            type="button"
            className="link"
            onClick={resend}
            disabled={cooldown > 0 || busy}
          >
            {cooldown > 0 ? `Resend in ${cooldown}s` : 'Resend code'}
          </button>
        </div>
        <div className="login-toggle">
          <button type="button" className="link" onClick={onBack}>← Back to sign in</button>
        </div>
      </form>
    </div>
  )
}

function ForgotScreen({ onSent, onBack }) {
  const [email, setEmail] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)

  async function submit(e) {
    e.preventDefault()
    if (busy) return
    setBusy(true)
    setError(null)
    try {
      await api.forgotPassword(email.trim().toLowerCase())
      onSent(email.trim().toLowerCase())
    } catch (err) {
      setError(err.message || 'Failed to send reset code.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="login-wrap">
      <form className="login-card" onSubmit={submit}>
        <div className="login-brand">
          <div className="brand-mark">N</div>
          <div>
            <div className="brand-text">Forgot password</div>
            <div className="brand-sub">We'll email you a 6-digit code</div>
          </div>
        </div>
        <p className="login-hint">
          Enter your account email and we'll send a reset code. The code expires in 30 minutes.
        </p>
        <label>
          <span>Email</span>
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            autoComplete="email"
            autoFocus
            required
          />
        </label>
        {error && <div className="login-error">{error}</div>}
        <button type="submit" className="primary login-submit" disabled={busy || !email}>
          {busy ? 'Sending…' : 'Send reset code'}
        </button>
        <div className="login-toggle">
          <button type="button" className="link" onClick={onBack}>← Back to sign in</button>
        </div>
      </form>
    </div>
  )
}

function ResetScreen({ email, onReset, onBack }) {
  const [code, setCode] = useState('')
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)

  async function submit(e) {
    e.preventDefault()
    if (busy) return
    if (!/^\d{6}$/.test(code)) {
      setError('Enter the 6-digit code from the email.')
      return
    }
    if (password.length < 8) {
      setError('Password must be at least 8 characters.')
      return
    }
    setBusy(true)
    setError(null)
    try {
      const u = await api.resetPassword(email, code, password)
      onReset(u)
    } catch (err) {
      setError(err.message || 'Reset failed')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="login-wrap">
      <form className="login-card" onSubmit={submit}>
        <div className="login-brand">
          <div className="brand-mark">N</div>
          <div>
            <div className="brand-text">Reset password</div>
            <div className="brand-sub">Enter the code and a new password</div>
          </div>
        </div>
        <p className="login-hint">
          We sent a code to <strong style={{ color: 'var(--text)' }}>{email}</strong>.
        </p>
        <label>
          <span>Reset code</span>
          <input
            type="text"
            inputMode="numeric"
            pattern="\d{6}"
            maxLength={6}
            className="otp-input"
            value={code}
            onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
            autoFocus
            autoComplete="one-time-code"
            required
          />
        </label>
        <label>
          <span>New password</span>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="new-password"
            minLength={8}
            required
          />
        </label>
        {error && <div className="login-error">{error}</div>}
        <button type="submit" className="primary login-submit" disabled={busy || code.length !== 6 || password.length < 8}>
          {busy ? 'Resetting…' : 'Reset password and sign in'}
        </button>
        <div className="login-toggle">
          <button type="button" className="link" onClick={onBack}>← Back to sign in</button>
        </div>
      </form>
    </div>
  )
}

function AuthScreen({ initialMode = 'login', onLoggedIn, registrationMode }) {
  const [mode, setMode] = useState(initialMode)
  const [username, setUsername] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [twoFactorCode, setTwoFactorCode] = useState('')
  const [twoFactorRequired, setTwoFactorRequired] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const [pendingEmail, setPendingEmail] = useState('')
  const [pendingCooldown, setPendingCooldown] = useState(60)
  const [inviteCode, setInviteCode] = useState('')

  function switchMode(next) {
    setMode(next)
    setError(null)
    setPassword('')
    setInviteCode('')
  }

  async function submit(e) {
    e.preventDefault()
    if (busy) return
    setBusy(true)
    setError(null)
    try {
      await api.me()
      if (mode === 'login') {
        try {
          const u = await api.login(username, password, twoFactorCode || undefined)
          onLoggedIn(u)
        } catch (err) {
          if (err.status === 401 && err.body?.two_factor_required) {
            setTwoFactorRequired(true)
            setError(twoFactorCode ? 'Wrong 2FA code. Try again.' : null)
          } else if (err.status === 401) {
            setError('Invalid username or password. (If you just registered, verify your email first.)')
          } else {
            setError(err.message)
          }
        }
      } else {
        const r = await api.register(username, email, password, inviteCode)
        setPendingEmail(email)
        setPendingCooldown(r.resend_available_in || 60)
        setInviteCode('')
        setMode('code')
      }
    } catch (err) {
      setError(err.message || 'Something went wrong')
    } finally {
      setBusy(false)
    }
  }

  if (mode === 'code') {
    return (
      <CodeScreen
        email={pendingEmail}
        initialCooldown={pendingCooldown}
        onVerified={onLoggedIn}
        onBack={() => switchMode('login')}
      />
    )
  }

  if (mode === 'forgot') {
    return (
      <ForgotScreen
        onSent={(em) => { setPendingEmail(em); setMode('reset') }}
        onBack={() => switchMode('login')}
      />
    )
  }

  if (mode === 'reset') {
    return (
      <ResetScreen
        email={pendingEmail}
        onReset={(result) => {
          if (result.two_factor_required) {
            switchMode('login')
            setUsername(result.username || '')
            setTwoFactorRequired(true)
            setTwoFactorCode('')
            setError('Password reset. Sign in with your new password and authenticator code.')
          } else {
            onLoggedIn(result)
          }
        }}
        onBack={() => switchMode('login')}
      />
    )
  }

  const isRegister = mode === 'register'
  const inviteRequired = registrationMode === 'invite'

  return (
    <div className="login-wrap">
      <form className="login-card" onSubmit={submit}>
        <div className="login-brand">
          <div className="brand-mark">N</div>
          <div>
            <div className="brand-text">AI Chat Hub</div>
            <div className="brand-sub">
              {isRegister ? (inviteRequired ? 'Create an invited account' : 'Create an account') : 'Sign in to continue'}
            </div>
          </div>
        </div>
        <label>
          <span>Username</span>
          <input
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoComplete="username"
            autoFocus
            required
          />
        </label>
        {isRegister && (
          <label>
            <span>Email</span>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              autoComplete="email"
              required
            />
          </label>
        )}
        {isRegister && inviteRequired && (
          <label>
            <span>Invitation code</span>
            <input
              type="text"
              value={inviteCode}
              onChange={(e) => setInviteCode(e.target.value.toUpperCase().slice(0, 24))}
              autoComplete="off"
              spellCheck={false}
              maxLength={24}
              placeholder="XXXX-XXXX-XXXX-XXXX-XXXX"
              required
            />
          </label>
        )}
        <label>
          <span>Password</span>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete={isRegister ? 'new-password' : 'current-password'}
            minLength={isRegister ? 8 : undefined}
            required
          />
        </label>
        {twoFactorRequired && !isRegister && (
          <label>
            <span>Two-factor code</span>
            <input
              type="text"
              inputMode="numeric"
              autoComplete="one-time-code"
              value={twoFactorCode}
              onChange={(e) => setTwoFactorCode(e.target.value)}
              placeholder="6-digit code or recovery code"
              autoFocus
              required
            />
          </label>
        )}
        {error && <div className="login-error">{error}</div>}
        <button
          type="submit"
          className="primary login-submit"
          disabled={busy || !username || !password
            || (isRegister && (!email || (inviteRequired && !inviteCode)))}
        >
          {busy ? (isRegister ? 'Creating…' : 'Signing in…') : (isRegister ? 'Create account' : 'Sign in')}
        </button>
        {!isRegister && (
          <div className="login-toggle" style={{ marginTop: -4 }}>
            <button type="button" className="link" onClick={() => switchMode('forgot')}>Forgot password?</button>
          </div>
        )}
        <div className="login-toggle">
          {isRegister ? (
            <>Already have an account? <button type="button" className="link" onClick={() => switchMode('login')}>Sign in</button></>
          ) : registrationMode === 'closed' ? (
            <span>New account registration is currently closed.</span>
          ) : (
            <>No account yet? <button type="button" className="link" onClick={() => switchMode('register')}>Create one</button></>
          )}
        </div>
      </form>
    </div>
  )
}

function CopyButton({ text, label = 'Copy' }) {
  const [copied, setCopied] = useState(false)
  async function copy() {
    try {
      await navigator.clipboard.writeText(text)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch {}
  }
  return (
    <button type="button" className="copy-btn" onClick={copy} title="Copy to clipboard">
      {copied ? '✓ Copied' : label}
    </button>
  )
}

function MessageBody({ role, content }) {
  if (role === 'user') {
    return <div className="bubble user-bubble">{content}</div>
  }
  return (
    <div className="bubble assistant-bubble">
      <Suspense fallback={<div className="markdown-fallback">{content}</div>}>
        <MarkdownBody content={content} />
      </Suspense>
    </div>
  )
}

function AttachmentTile({ att, onRemove, compact, included = true, onToggle, onPreview }) {
  const isImage = att.kind === 'image' || att.kind === 'generated_image'
  const url = mediaUrl(att.url)
  if (isImage) {
    return (
      <div className={`att-tile image ${compact ? 'compact' : ''} ${included ? '' : 'excluded'}`}>
        <a href={url} target="_blank" rel="noreferrer">
          <img src={url} alt={att.original_name} />
        </a>
        {onToggle && (
          <label className="att-include" title={included ? 'Exclude from next message' : 'Include in next message'}>
            <input
              type="checkbox"
              checked={included}
              onChange={() => onToggle(att.id)}
              aria-label={`Include ${att.original_name} in next message`}
            />
          </label>
        )}
        {onRemove && (
          <button type="button" className="att-remove" onClick={() => onRemove(att.id)} title="Remove">×</button>
        )}
      </div>
    )
  }
  return (
    <div className={`att-tile doc ${compact ? 'compact' : ''} ${included ? '' : 'excluded'}`}>
      <div className="att-doc-icon">{(fileExt(att.original_name) || 'DOC').toUpperCase()}</div>
      <div className="att-doc-meta">
        <a className="att-doc-name" href={url} title={att.original_name} download>{att.original_name}</a>
        <div className="att-doc-size">{humanSize(att.size)}{att.has_text ? ' · text extracted' : ''}</div>
        {onPreview && att.has_text && (
          <button
            type="button"
            className="link att-preview"
            onClick={(event) => onPreview(att, event.currentTarget)}
          >Preview text</button>
        )}
      </div>
      {onToggle && (
        <label className="att-include" title={included ? 'Exclude from next message' : 'Include in next message'}>
          <input
            type="checkbox"
            checked={included}
            onChange={() => onToggle(att.id)}
            aria-label={`Include ${att.original_name} in next message`}
          />
        </label>
      )}
      {onRemove && (
        <button type="button" className="att-remove" onClick={() => onRemove(att.id)} title="Remove">×</button>
      )}
    </div>
  )
}

function UploadJobTile({ job, onCancel, onRetry, onDismiss }) {
  const retryable = job.status === 'error' || job.status === 'canceled'
  return (
    <div className={`upload-job ${job.status}`} role="status">
      <div className="upload-job-meta">
        <strong title={job.name}>{job.name}</strong>
        <small>
          {job.status === 'uploading' && `Uploading · ${job.progress}%`}
          {job.status === 'queued' && 'Waiting to upload'}
          {job.status === 'error' && (job.error || 'Upload failed')}
          {job.status === 'canceled' && 'Upload canceled'}
        </small>
      </div>
      <progress
        max="100"
        value={job.status === 'error' || job.status === 'canceled' ? 0 : job.progress}
        aria-label={`Upload progress for ${job.name}`}
      />
      <div className="upload-job-actions">
        {job.status === 'uploading' && (
          <button type="button" className="link" onClick={() => onCancel(job.key)}>Cancel</button>
        )}
        {retryable && (
          <button type="button" className="link" onClick={() => onRetry(job.key)}>Retry</button>
        )}
        {retryable && (
          <button type="button" className="link" onClick={() => onDismiss(job.key)}>Dismiss</button>
        )}
      </div>
    </div>
  )
}

function ConvoSettingsPanel({ convo, onSaved, onClose }) {
  const [systemPrompt, setSystemPrompt] = useState(convo.system_prompt || '')
  const [temperature, setTemperature] = useState(convo.temperature ?? 0.7)
  const [maxTokens, setMaxTokens] = useState(convo.max_tokens ?? 1024)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)

  async function save() {
    setBusy(true); setError(null)
    try {
      const updated = await api.updateConversation(convo.id, {
        system_prompt: systemPrompt,
        temperature: Number(temperature),
        max_tokens: Number(maxTokens),
      })
      onSaved(updated)
    } catch (e) { setError(e.message) }
    finally { setBusy(false) }
  }

  return (
    <div className="convo-settings">
      <label className="cs-full">
        <span>System prompt — applies to this conversation only</span>
        <textarea
          rows={3}
          maxLength={4000}
          value={systemPrompt}
          onChange={(e) => setSystemPrompt(e.target.value)}
          placeholder="e.g. You are a concise senior Python reviewer. Answer in bullet points."
        />
      </label>
      <div className="cs-row">
        <label>
          <span>Temperature: {Number(temperature).toFixed(1)}</span>
          <input
            type="range" min={0} max={2} step={0.1}
            value={temperature}
            onChange={(e) => setTemperature(e.target.value)}
          />
        </label>
        <label>
          <span>Max tokens</span>
          <input
            type="number" min={64} max={8192} step={64}
            value={maxTokens}
            onChange={(e) => setMaxTokens(e.target.value)}
          />
        </label>
        <div className="cs-actions">
          <button type="button" className="primary" onClick={save} disabled={busy}>
            {busy ? 'Saving…' : 'Save'}
          </button>
          <button type="button" className="link" onClick={onClose}>Close</button>
        </div>
      </div>
      {error && <div className="login-error">{error}</div>}
    </div>
  )
}

function MessageRow({ m, modelLabel, busy, onEdit, onRegenerate }) {
  const [editing, setEditing] = useState(false)
  const [draft, setDraft] = useState(m.content || '')
  const isPending = m.id === 'pending-regen' || (typeof m.id === 'string' && m.id.startsWith('pending'))

  function startEdit() {
    setDraft(m.content || '')
    setEditing(true)
  }
  async function saveEdit() {
    const next = draft.trim()
    if (!next || next === m.content) { setEditing(false); return }
    await onEdit(m.id, next)
    setEditing(false)
  }

  return (
    <div className={`msg ${m.role}`}>
      <div className="avatar">{m.role === 'user' ? 'U' : 'AI'}</div>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div className="role">
          <span>{m.role === 'user' ? 'You' : modelLabel}</span>
          {m.role === 'assistant' && m.content && <CopyButton text={m.content} />}
          {!isPending && !editing && !busy && (
            <span style={{ display: 'inline-flex', gap: 6, marginLeft: 8 }}>
              {m.role === 'user' && (
                <button className="link" type="button" onClick={startEdit} title="Edit message">✎ Edit</button>
              )}
              {!busy && (
                <button
                  className="link"
                  type="button"
                  onClick={() => onRegenerate(m.id)}
                  title="Regenerate from this message"
                >⟳ Regenerate</button>
              )}
            </span>
          )}
        </div>
        {(m.attachments || []).length > 0 && (
          <div className="msg-attachments">
            {m.attachments.map((a) => <AttachmentTile key={a.id} att={a} />)}
          </div>
        )}
        {editing ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            <textarea
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              rows={Math.min(10, Math.max(2, draft.split('\n').length))}
              style={{ width: '100%', resize: 'vertical' }}
            />
            <div style={{ display: 'flex', gap: 8 }}>
              <button type="button" className="primary" onClick={saveEdit}>Save</button>
              <button type="button" className="link" onClick={() => setEditing(false)}>Cancel</button>
              <span style={{ color: 'var(--muted, #888)', fontSize: 12, alignSelf: 'center' }}>
                Tip: after saving, click ⟳ Regenerate to re-roll the reply.
              </span>
            </div>
          </div>
        ) : m.streaming && !m.content ? (
          <div className="bubble assistant-bubble">
            <span className="typing"><span/><span/><span/></span>
          </div>
        ) : m.content ? (
          <MessageBody role={m.role} content={m.content} />
        ) : null}
      </div>
    </div>
  )
}

export default function App() {
  const [authChecked, setAuthChecked] = useState(false)
  const [user, setUser] = useState(null)
  const [registrationMode, setRegistrationMode] = useState('closed')
  const [models, setModels] = useState([])
  const [defaultModel, setDefaultModel] = useState('')
  const [availabilityCheckedAt, setAvailabilityCheckedAt] = useState(null)
  const [conversations, setConversations] = useState([])
  const [activeId, setActiveId] = useState(null)
  const [active, setActive] = useState(null)
  const [draft, setDraft] = useState('')
  const [sending, setSending] = useState(false)
  const [error, setError] = useState(null)
  const [bootError, setBootError] = useState(null)
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const [theme, setTheme] = useState(() => {
    try { return localStorage.getItem('aichat-theme') === 'light' ? 'light' : 'dark' }
    catch { return 'dark' }
  })
  const [search, setSearch] = useState('')
  const [conversationView, setConversationView] = useState('active')
  const [conversationCounts, setConversationCounts] = useState({ active: 0, archived: 0 })
  const [conversationNextCursor, setConversationNextCursor] = useState(null)
  const [conversationLoadingMore, setConversationLoadingMore] = useState(false)
  const [conversationMenuId, setConversationMenuId] = useState(null)
  const [conversationNotice, setConversationNotice] = useState(null)
  const [showConvoSettings, setShowConvoSettings] = useState(false)
  const [mode, setMode] = useState('chat')
  const [pendingAttachments, setPendingAttachments] = useState([])
  const [excludedAttachmentIds, setExcludedAttachmentIds] = useState([])
  const [attachmentNotice, setAttachmentNotice] = useState(null)
  const [previewAttachment, setPreviewAttachment] = useState(null)
  const [uploadJobs, setUploadJobs] = useState([])
  const [draggingFiles, setDraggingFiles] = useState(false)
  const [attachmentMenuOpen, setAttachmentMenuOpen] = useState(false)
  const [attachmentLimits, setAttachmentLimits] = useState({
    max_files_per_message: 8,
    max_file_bytes: MAX_FILE_BYTES,
    max_bytes_per_message: 20 * 1024 * 1024,
  })
  const [imageModels, setImageModels] = useState([])
  const [imageModel, setImageModel] = useState('')
  const [imagePrompt, setImagePrompt] = useState('')
  const [imageBusy, setImageBusy] = useState(false)
  const [imageParams, setImageParams] = useState({ width: 1024, height: 1024, steps: 4, seed: 0 })
  const [imageGallery, setImageGallery] = useState([])
  const [imageGalleryNextCursor, setImageGalleryNextCursor] = useState(null)
  const [imageGalleryLoadingMore, setImageGalleryLoadingMore] = useState(false)
  const [loadingEarlierMessages, setLoadingEarlierMessages] = useState(false)
  const chatEndRef = useRef(null)
  const chatAreaRef = useRef(null)
  const chatScrollRestoreRef = useRef(null)
  const textareaRef = useRef(null)
  const imageInputRef = useRef(null)
  const documentInputRef = useRef(null)
  const attachButtonRef = useRef(null)
  const uploadFilesRef = useRef(new Map())
  const uploadControllersRef = useRef(new Map())
  const uploadSequenceRef = useRef(0)
  const previewReturnFocusRef = useRef(null)
  const abortRef = useRef(null)
  const sidebarRef = useRef(null)
  const menuRef = useRef(null)
  const conversationMenuButtonRef = useRef(null)
  const conversationQueryKeyRef = useRef('active\u0000')
  const activeIdRef = useRef(activeId)
  activeIdRef.current = activeId
  conversationQueryKeyRef.current = `${conversationView}\u0000${search.trim()}`

  useEffect(() => () => {
    for (const controller of uploadControllersRef.current.values()) controller.abort()
    uploadControllersRef.current.clear()
    uploadFilesRef.current.clear()
  }, [])

  useEffect(() => {
    document.documentElement.dataset.theme = theme
    try { localStorage.setItem('aichat-theme', theme) } catch {}
  }, [theme])

  useEffect(() => {
    if (!sidebarOpen) return
    const sidebar = sidebarRef.current
    const menuButton = menuRef.current
    const focusable = () => [...sidebar.querySelectorAll('button:not(:disabled), input, a[href]')]
      .filter((element) => element.getClientRects().length > 0)
    focusable()[0]?.focus()
    function trapFocus(event) {
      if (event.key === 'Escape') { setSidebarOpen(false); return }
      if (event.key !== 'Tab') return
      const items = focusable()
      const first = items[0], last = items.at(-1)
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus() }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus() }
    }
    document.addEventListener('keydown', trapFocus)
    return () => {
      document.removeEventListener('keydown', trapFocus)
      menuButton?.focus()
    }
  }, [sidebarOpen])

  useEffect(() => {
    if (!attachmentMenuOpen) return
    function closeAttachmentMenu(event) {
      if (event.key !== 'Escape') return
      setAttachmentMenuOpen(false)
      attachButtonRef.current?.focus()
    }
    document.addEventListener('keydown', closeAttachmentMenu)
    return () => document.removeEventListener('keydown', closeAttachmentMenu)
  }, [attachmentMenuOpen])

  useEffect(() => {
    if (conversationMenuId == null) return
    function closeConversationMenu(event) {
      if (event.type === 'keydown' && event.key !== 'Escape') return
      if (event.type === 'pointerdown' && event.target.closest?.('[data-conversation-menu]')) return
      setConversationMenuId(null)
      if (event.type === 'keydown') conversationMenuButtonRef.current?.focus()
    }
    document.addEventListener('keydown', closeConversationMenu)
    document.addEventListener('pointerdown', closeConversationMenu)
    return () => {
      document.removeEventListener('keydown', closeConversationMenu)
      document.removeEventListener('pointerdown', closeConversationMenu)
    }
  }, [conversationMenuId])

  useEffect(() => {
    let cancelled = false
    api.me()
      .then((u) => {
        if (cancelled) return
        setRegistrationMode(u.registration_mode || 'closed')
        setUser(u.username ? u : null)
        setAuthChecked(true)
      })
      .catch((e) => {
        if (cancelled) return
        setBootError(e.message)
        setAuthChecked(true)
      })
    return () => { cancelled = true }
  }, [])

  useEffect(() => {
    if (!user) return
    let cancelled = false
    Promise.all([
      api.listModels(),
      api.listConversations(),
      api.listImageModels().catch(() => ({ models: [], default: '' })),
      api.listAttachments('generated_image').catch(() => []),
    ])
      .then(([m, c, im, gallery]) => {
        if (cancelled) return
        setModels(m.models)
        setDefaultModel(m.default)
        setAvailabilityCheckedAt(m.availability_checked_at || null)
        setAttachmentLimits((limits) => ({ ...limits, ...(m.attachment_limits || {}) }))
        const conversationPage = normalizeConversationPage(c, 'active')
        setConversations(conversationPage.results)
        setConversationCounts(conversationPage.counts)
        setConversationNextCursor(conversationPage.nextCursor)
        setConversationLoadingMore(false)
        setImageModels(im.models || [])
        setImageModel(im.default || (im.models?.[0]?.id) || '')
        const galleryPage = normalizeAttachmentPage(gallery)
        setImageGallery(galleryPage.results)
        setImageGalleryNextCursor(galleryPage.nextCursor)
      })
      .catch((e) => {
        if (cancelled) return
        if (e.status === 401 || e.status === 403) {
          clearAttachmentWork()
          setUser(null)
          return
        }
        setBootError(e.message)
      })
    return () => { cancelled = true }
  }, [user])

  useEffect(() => {
    if (!user) return
    let cancelled = false
    const t = setTimeout(() => {
      api.listConversations(search.trim() || undefined, conversationView)
        .then((page) => {
          if (cancelled) return
          const normalized = normalizeConversationPage(page, conversationView)
          setConversations(normalized.results)
          setConversationCounts(normalized.counts)
          setConversationNextCursor(normalized.nextCursor)
          setConversationLoadingMore(false)
        })
        .catch(() => { if (!cancelled) setConversationLoadingMore(false) })
    }, 300)
    return () => { cancelled = true; clearTimeout(t) }
  }, [search, user, conversationView])

  useEffect(() => {
    if (!activeId) return
    let cancelled = false
    api.getConversation(activeId)
      .then((c) => !cancelled && setActive(c))
      .catch((e) => !cancelled && setError(e.message))
    return () => { cancelled = true }
  }, [activeId])

  useEffect(() => {
    const restoration = chatScrollRestoreRef.current
    if (restoration && chatAreaRef.current) {
      chatAreaRef.current.scrollTop = restoration.top
        + (chatAreaRef.current.scrollHeight - restoration.height)
      chatScrollRestoreRef.current = null
      return
    }
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [active?.messages?.length, sending])

  useEffect(() => {
    const t = textareaRef.current
    if (!t) return
    t.style.height = 'auto'
    t.style.height = Math.min(t.scrollHeight, 200) + 'px'
  }, [draft])

  const currentModelId = active?.model_id || defaultModel

  const currentModel = useMemo(
    () => models.find((x) => x.id === currentModelId),
    [models, currentModelId],
  )

  const activeModelUnavailable = Boolean(active?.model_id && !currentModel)
  const defaultModelSpec = models.find((model) => model.id === defaultModel)
  const modelLabel = currentModel
    ? `${currentModel.name} · ${currentModel.vendor}`
    : currentModelId ? `${currentModelId.split('/').pop()} · unavailable` : 'No model available'
  const currentCapabilities = capabilitiesFor(currentModel)
  const supportsVision = currentCapabilities.input_modalities.includes('image')
  const imageExtensions = currentCapabilities.attachment_extensions
    .filter((extension) => !DOCUMENT_EXTENSIONS.includes(extension))
  const imageAccept = imageExtensions.map((extension) => `.${extension}`).join(',')
  const pendingImages = pendingAttachments.filter((attachment) =>
    ['image', 'generated_image'].includes(attachment.kind))
  const excludedAttachmentSet = useMemo(
    () => new Set(excludedAttachmentIds),
    [excludedAttachmentIds],
  )
  const includedPendingAttachments = pendingAttachments.filter(
    (attachment) => !excludedAttachmentSet.has(attachment.id),
  )
  const queuedImages = uploadJobs.filter((job) => job.kind === 'image')
  const uploadingCount = uploadJobs.filter((job) => job.status === 'uploading').length
  const incompatiblePending = includedPendingAttachments.filter((attachment) =>
    !attachmentIsCompatible(attachment, currentCapabilities))
  const attachmentsBlocked = incompatiblePending.length > 0
  const imageLimitReached = pendingImages.length + queuedImages.length
    >= currentCapabilities.max_images
  const fileLimitReached = pendingAttachments.length + uploadJobs.length
    >= attachmentLimits.max_files_per_message
  const maxImageBytes = Math.min(
    attachmentLimits.max_file_bytes,
    currentCapabilities.max_image_bytes || attachmentLimits.max_file_bytes,
  )
  const historicalImagesOmitted = Boolean(active?.messages?.some((message) =>
    (message.attachments || []).some((attachment) =>
      ['image', 'generated_image'].includes(attachment.kind)
      && !attachmentIsCompatible(attachment, currentCapabilities))))
  const groupedModels = useMemo(() => PURPOSE_GROUPS.map(([purpose, label]) => ({
    purpose,
    label,
    models: models.filter((model) => (model.purpose || 'assistant') === purpose),
  })).filter((group) => group.models.length > 0), [models])

  const currentImageSpec = useMemo(
    () => imageModels.find((m) => m.id === imageModel),
    [imageModels, imageModel],
  )

  function handleSwitchImageModel(id) {
    setImageModel(id)
    const spec = imageModels.find((m) => m.id === id)
    const dims = spec?.allowed_dims
    if (!dims) return
    setImageParams((p) => ({
      ...p,
      width: dims.includes(p.width) ? p.width : 1024,
      height: dims.includes(p.height) ? p.height : 1024,
      steps: Math.min(p.steps, spec.max_steps || p.steps),
    }))
  }

  async function startNewChat(modelId = defaultModel) {
    if (sending) return
    if (!modelId) {
      setError('No chat models are currently available.')
      return
    }
    try {
      const c = await api.createConversation(modelId)
      setConversations((prev) => [c, ...prev])
      setConversationCounts((counts) => ({ ...counts, active: counts.active + 1 }))
      setConversationView('active')
      setSearch('')
      setConversationNotice(null)
      setActiveId(c.id)
      setActive(c)
      setError(null)
      setSidebarOpen(false)
    } catch (e) {
      setError(e.message)
    }
  }

  async function startUpload(job) {
    const stored = uploadFilesRef.current.get(job.key)
    if (!stored) return
    const controller = new AbortController()
    uploadControllersRef.current.set(job.key, controller)
    setUploadJobs((jobs) => jobs.map((item) => item.key === job.key
      ? { ...item, status: 'uploading', progress: 0, error: null }
      : item))
    try {
      const attachment = await api.uploadAttachment(stored.file, job.modelId, {
        signal: controller.signal,
        onProgress: (progress) => setUploadJobs((jobs) => jobs.map((item) =>
          item.key === job.key ? { ...item, progress } : item)),
      })
      setPendingAttachments((attachments) => (
        attachments.some((item) => item.id === attachment.id)
          ? attachments
          : [...attachments, attachment]
      ))
      setExcludedAttachmentIds((ids) => ids.filter((id) => id !== attachment.id))
      if (attachment.deduplicated) {
        setAttachmentNotice(`${attachment.original_name} was already uploaded, so the existing private copy was reused.`)
      }
      setUploadJobs((jobs) => jobs.filter((item) => item.key !== job.key))
      uploadFilesRef.current.delete(job.key)
    } catch (uploadError) {
      setUploadJobs((jobs) => jobs.map((item) => item.key === job.key
        ? {
            ...item,
            status: uploadError.name === 'AbortError' ? 'canceled' : 'error',
            error: uploadError.name === 'AbortError' ? null : uploadError.message,
          }
        : item))
    } finally {
      uploadControllersRef.current.delete(job.key)
    }
  }

  function queueFiles(rawFiles, requestedKind = null) {
    const files = Array.from(rawFiles || [])
    if (!files.length) return
    setAttachmentMenuOpen(false)
    setDraggingFiles(false)
    setError(null)
    setAttachmentNotice(null)
    if (sending) {
      setError('Wait for the current response to finish before adding files.')
      return
    }
    if (!currentModel) {
      setError('Choose an available model before adding files.')
      return
    }

    let fileSlots = Math.max(
      0,
      attachmentLimits.max_files_per_message - pendingAttachments.length - uploadJobs.length,
    )
    let imageSlots = Math.max(
      0,
      currentCapabilities.max_images - pendingImages.length - queuedImages.length,
    )
    let bytesAvailable = Math.max(
      0,
      attachmentLimits.max_bytes_per_message
        - pendingAttachments.reduce((total, attachment) => total + attachment.size, 0)
        - uploadJobs.reduce((total, job) => total + job.size, 0),
    )
    const accepted = []
    const rejected = []

    for (const file of files) {
      const extension = uploadExtension(file)
      const kind = requestedKind || (DOCUMENT_EXTENSIONS.includes(extension) ? 'document' : 'image')
      const allowedExtensions = kind === 'image'
        ? imageExtensions
        : currentCapabilities.document_extensions
      if (fileSlots <= 0) {
        rejected.push(`At most ${attachmentLimits.max_files_per_message} files are allowed per message.`)
        break
      }
      if (!allowedExtensions.includes(extension)) {
        rejected.push(`.${extension || '?'} isn't supported here.`)
        continue
      }
      if (kind === 'image' && imageSlots <= 0) {
        rejected.push(`${currentModel.name} accepts at most ${currentCapabilities.max_images} image(s).`)
        continue
      }
      const maxBytes = kind === 'image' ? maxImageBytes : attachmentLimits.max_file_bytes
      if (file.size > maxBytes) {
        rejected.push(`${file.name || 'This file'} exceeds the ${humanSize(maxBytes)} limit.`)
        continue
      }
      if (file.size > bytesAvailable) {
        rejected.push(`Attachments exceed the ${humanSize(attachmentLimits.max_bytes_per_message)} message limit.`)
        continue
      }

      const key = `upload-${Date.now()}-${uploadSequenceRef.current += 1}`
      const job = {
        key,
        name: (file.name || `pasted-image.${extension || 'png'}`).slice(0, 120),
        size: file.size,
        kind,
        modelId: currentModelId,
        progress: 0,
        status: 'queued',
        error: null,
      }
      uploadFilesRef.current.set(key, { file })
      accepted.push(job)
      fileSlots -= 1
      bytesAvailable -= file.size
      if (kind === 'image') imageSlots -= 1
    }

    if (rejected.length) {
      setError(`${rejected[0]}${rejected.length > 1 ? ` (${rejected.length - 1} more rejected)` : ''}`)
    }
    if (!accepted.length) return
    setUploadJobs((jobs) => [...jobs, ...accepted])
    for (const job of accepted) startUpload(job)
  }

  function handlePickFiles(event, requestedKind) {
    queueFiles(event.target.files, requestedKind)
    event.target.value = ''
  }

  function cancelUpload(key) {
    uploadControllersRef.current.get(key)?.abort()
  }

  function retryUpload(key) {
    const job = uploadJobs.find((item) => item.key === key)
    if (!job || !uploadFilesRef.current.has(key)) return
    startUpload({ ...job, modelId: currentModelId })
  }

  function dismissUpload(key) {
    uploadControllersRef.current.get(key)?.abort()
    uploadControllersRef.current.delete(key)
    uploadFilesRef.current.delete(key)
    setUploadJobs((jobs) => jobs.filter((item) => item.key !== key))
  }

  function clearAttachmentWork() {
    abortRef.current?.abort()
    abortRef.current = null
    for (const controller of uploadControllersRef.current.values()) controller.abort()
    uploadControllersRef.current.clear()
    uploadFilesRef.current.clear()
    setUploadJobs([])
    setPendingAttachments([])
    setExcludedAttachmentIds([])
    setAttachmentNotice(null)
    setPreviewAttachment(null)
    previewReturnFocusRef.current = null
    setDraggingFiles(false)
    setAttachmentMenuOpen(false)
    setDraft('')
  }

  function handleComposerPaste(event) {
    const files = Array.from(event.clipboardData?.files || [])
    if (!files.length) return
    event.preventDefault()
    queueFiles(files)
  }

  async function removePending(id) {
    try { await api.deleteAttachment(id) } catch {}
    setPendingAttachments((prev) => prev.filter((a) => a.id !== id))
    setExcludedAttachmentIds((ids) => ids.filter((attachmentId) => attachmentId !== id))
    if (previewAttachment?.id === id) closeDocumentPreview()
  }

  async function removeIncompatibleAttachments() {
    await Promise.all(incompatiblePending.map(async (attachment) => {
      try { await api.deleteAttachment(attachment.id) } catch {}
    }))
    const incompatibleIds = new Set(incompatiblePending.map((attachment) => attachment.id))
    setPendingAttachments((items) => items.filter((attachment) => !incompatibleIds.has(attachment.id)))
    setExcludedAttachmentIds((ids) => ids.filter((id) => !incompatibleIds.has(id)))
  }

  function toggleAttachmentInclusion(id) {
    setAttachmentNotice(null)
    setExcludedAttachmentIds((ids) => (
      ids.includes(id) ? ids.filter((item) => item !== id) : [...ids, id]
    ))
  }

  function openDocumentPreview(attachment, trigger) {
    previewReturnFocusRef.current = trigger
    setPreviewAttachment(attachment)
  }

  function closeDocumentPreview() {
    const returnFocus = previewReturnFocusRef.current
    setPreviewAttachment(null)
    previewReturnFocusRef.current = null
    requestAnimationFrame(() => returnFocus?.isConnected && returnFocus.focus())
  }

  async function handleGenerate(e) {
    e?.preventDefault?.()
    const prompt = imagePrompt.trim()
    if (!prompt || imageBusy) return
    setImageBusy(true)
    setError(null)
    try {
      const r = await api.generateImage({
        prompt,
        model_id: imageModel,
        ...imageParams,
      })
      setImageGallery((prev) => [r.attachment, ...prev])
    } catch (err) {
      setError(err.message)
    } finally {
      setImageBusy(false)
    }
  }

  async function loadEarlierMessages() {
    const conversationId = active?.id
    const cursor = active?.message_page?.older_cursor
    if (!conversationId || !cursor || loadingEarlierMessages) return
    setLoadingEarlierMessages(true)
    try {
      const page = await api.listEarlierMessages(conversationId, cursor)
      if (activeIdRef.current !== conversationId) return
      const scrollArea = chatAreaRef.current
      if (scrollArea) {
        chatScrollRestoreRef.current = {
          height: scrollArea.scrollHeight,
          top: scrollArea.scrollTop,
        }
      }
      setActive((current) => {
        if (!current || current.id !== conversationId) return current
        const currentIds = new Set(current.messages.map((message) => message.id))
        const earlier = page.results.filter((message) => !currentIds.has(message.id))
        return {
          ...current,
          messages: [...earlier, ...current.messages],
          message_page: {
            count: page.count,
            older_cursor: page.older_cursor,
          },
        }
      })
    } catch (loadError) {
      if (activeIdRef.current === conversationId) setError(loadError.message)
    } finally {
      if (activeIdRef.current === conversationId) setLoadingEarlierMessages(false)
    }
  }

  async function loadMoreGallery() {
    if (!imageGalleryNextCursor || imageGalleryLoadingMore) return
    const cursor = imageGalleryNextCursor
    setImageGalleryLoadingMore(true)
    try {
      const page = normalizeAttachmentPage(
        await api.listAttachments('generated_image', cursor),
      )
      setImageGallery((current) => {
        const byId = new Map(current.map((item) => [item.id, item]))
        for (const item of page.results) byId.set(item.id, item)
        return [...byId.values()]
      })
      setImageGalleryNextCursor(page.nextCursor)
    } catch (loadError) {
      setError(loadError.message)
    } finally {
      setImageGalleryLoadingMore(false)
    }
  }

  async function handleSend(e) {
    e?.preventDefault?.()
    const text = draft.trim()
    if (sending || attachmentsBlocked || activeModelUnavailable) return
    if (!text && includedPendingAttachments.length === 0) return

    let convo = active
    if (!convo) {
      try {
        convo = await api.createConversation(currentModelId || defaultModel)
        setConversations((prev) => [convo, ...prev])
        setConversationCounts((counts) => ({ ...counts, active: counts.active + 1 }))
        setConversationView('active')
        setSearch('')
        setActiveId(convo.id)
        setActive(convo)
      } catch (err) { setError(err.message); return }
    }

    setError(null)
    setSending(true)
    setDraft('')

    const sendingAttachments = includedPendingAttachments
    setPendingAttachments((attachments) => attachments.filter(
      (attachment) => excludedAttachmentSet.has(attachment.id),
    ))

    const tmpUserId = `tmp-user-${Date.now()}`
    const streamingId = `streaming-${Date.now()}`

    setActive((c) => ({
      ...c,
      messages: [
        ...(c?.messages || []),
        { id: tmpUserId, role: 'user', content: text, attachments: sendingAttachments },
        { id: streamingId, role: 'assistant', content: '', streaming: true },
      ],
    }))

    let streamed = ''
    const controller = new AbortController()
    abortRef.current = controller

    await api.sendMessageStream(convo.id, text, undefined, sendingAttachments.map((a) => a.id), {
      onUserMessage: (userMsg) => {
        setActive((c) => ({
          ...c,
          messages: (c?.messages || []).map((m) =>
            m.id === tmpUserId ? { ...userMsg, attachments: sendingAttachments } : m,
          ),
        }))
      },
      onChunk: (chunk) => {
        streamed += chunk
        setActive((c) => ({
          ...c,
          messages: (c?.messages || []).map((m) =>
            m.id === streamingId ? { ...m, content: streamed } : m,
          ),
        }))
      },
      onDone: (final) => {
        setActive((c) => ({
          ...c,
          messages: (c?.messages || [])
            .filter((m) => m.id !== tmpUserId && m.id !== streamingId)
            .concat([final.user_message, final.assistant_message]),
          message_page: c?.message_page ? {
            ...c.message_page,
            count: c.message_page.count + 2,
          } : c?.message_page,
        }))
        setConversations((prev) => {
          const others = prev.filter((p) => p.id !== convo.id)
          return sortConversations([final.conversation, ...others])
        })
      },
      onError: (msg) => {
        setError(msg)
        setPendingAttachments((attachments) => {
          const existingIds = new Set(attachments.map((attachment) => attachment.id))
          return [...attachments, ...sendingAttachments.filter((attachment) => !existingIds.has(attachment.id))]
        })
        setActive((c) => ({
          ...c,
          messages: (c?.messages || []).filter(
            (m) => m.id !== tmpUserId && m.id !== streamingId,
          ),
        }))
      },
      onAbort: async () => {
        // Server persists the partial reply on disconnect; give it a beat,
        // then refetch so ids and content are authoritative.
        await new Promise((r) => setTimeout(r, 400))
        try {
          const fresh = await api.getConversation(convo.id)
          setActive(fresh)
          const refreshed = normalizeConversationPage(
            await api.listConversations(search.trim() || undefined, conversationView),
            conversationView,
          )
          setConversations(refreshed.results)
          setConversationCounts(refreshed.counts)
          setConversationNextCursor(refreshed.nextCursor)
        } catch { /* keep optimistic state */ }
      },
    }, controller.signal)

    abortRef.current = null
    setSending(false)
  }

  async function handleRename(c, ev) {
    ev?.stopPropagation?.()
    const title = prompt('Rename conversation:', c.title || '')
    if (title == null) return
    const trimmed = title.trim().slice(0, 200)
    if (!trimmed || trimmed === c.title) return
    try {
      const updated = await api.renameConversation(c.id, trimmed)
      setConversations((prev) => prev.map((x) => (x.id === c.id ? { ...x, title: updated.title } : x)))
      if (activeId === c.id) setActive((a) => (a ? { ...a, title: updated.title } : a))
    } catch (e) { setError(e.message) }
  }

  async function handlePin(c, ev) {
    ev?.stopPropagation?.()
    setConversationMenuId(null)
    try {
      const updated = await api.updateConversation(c.id, { is_pinned: !c.is_pinned })
      setConversations((prev) => sortConversations(
        prev.map((item) => (item.id === c.id ? { ...item, ...updated } : item)),
      ))
      if (activeId === c.id) setActive((current) => (current ? { ...current, ...updated } : current))
      setConversationNotice(updated.is_pinned ? 'Conversation pinned.' : 'Conversation unpinned.')
    } catch (e) { setError(e.message) }
  }

  async function handleArchive(c, ev) {
    ev?.stopPropagation?.()
    setConversationMenuId(null)
    const wasArchived = Boolean(c.archived_at)
    try {
      await api.updateConversation(c.id, { archived: !wasArchived })
      setConversations((prev) => prev.filter((item) => item.id !== c.id))
      setConversationCounts((counts) => ({
        active: Math.max(0, counts.active + (wasArchived ? 1 : -1)),
        archived: Math.max(0, counts.archived + (wasArchived ? -1 : 1)),
      }))
      if (activeId === c.id) { setActiveId(null); setActive(null) }
      setConversationNotice(
        wasArchived ? 'Conversation restored to Active.' : 'Conversation moved to Archived.',
      )
    } catch (e) { setError(e.message) }
  }

  async function handleDelete(c, ev) {
    ev?.stopPropagation?.()
    setConversationMenuId(null)
    if (!confirm('Permanently delete this conversation? This cannot be undone.')) return
    try {
      await api.deleteConversation(c.id)
      setConversations((prev) => prev.filter((item) => item.id !== c.id))
      const countKey = c.archived_at ? 'archived' : 'active'
      setConversationCounts((counts) => ({
        ...counts,
        [countKey]: Math.max(0, counts[countKey] - 1),
      }))
      if (activeId === c.id) { setActiveId(null); setActive(null) }
      setConversationNotice('Conversation permanently deleted.')
    } catch (e) { setError(e.message) }
  }

  function showConversationView(view) {
    setConversationView(view)
    setConversationNextCursor(null)
    setConversationLoadingMore(false)
    setConversationMenuId(null)
    setConversationNotice(null)
  }

  async function loadMoreConversations() {
    if (!conversationNextCursor || conversationLoadingMore) return
    const query = search.trim()
    const view = conversationView
    const queryKey = `${view}\u0000${query}`
    setConversationLoadingMore(true)
    try {
      const page = normalizeConversationPage(
        await api.listConversations(query || undefined, view, conversationNextCursor),
        view,
      )
      if (conversationQueryKeyRef.current !== queryKey) return
      setConversations((current) => {
        const byId = new Map(current.map((item) => [item.id, item]))
        for (const item of page.results) byId.set(item.id, item)
        return sortConversations([...byId.values()])
      })
      setConversationCounts(page.counts)
      setConversationNextCursor(page.nextCursor)
    } catch (loadError) {
      if (conversationQueryKeyRef.current === queryKey) setError(loadError.message)
    } finally {
      if (conversationQueryKeyRef.current === queryKey) setConversationLoadingMore(false)
    }
  }

  async function handleEditMessage(msgId, newContent) {
    if (!active) return
    try {
      const updated = await api.editMessage(msgId, newContent)
      setActive((c) => ({
        ...c,
        messages: c.messages.map((m) => (m.id === msgId ? { ...m, content: updated.content } : m)),
      }))
    } catch (e) { setError(e.message) }
  }

  async function handleRegenerate(msgId) {
    if (!active || sending || activeModelUnavailable) return
    setSending(true)
    setError(null)
    // Optimistic UI: drop messages from `msgId` onward (or just the last assistant
    // for an assistant target). Server is authoritative; refetch convo on done.
    let placeholder = null
    setActive((c) => {
      if (!c) return c
      const idx = c.messages.findIndex((m) => m.id === msgId)
      if (idx === -1) return c
      const target = c.messages[idx]
      const cutAt = target.role === 'assistant' ? idx : idx + 1
      const kept = c.messages.slice(0, cutAt)
      placeholder = { id: 'pending-regen', role: 'assistant', content: '', streaming: true, attachments: [] }
      return { ...c, messages: [...kept, placeholder] }
    })
    const controller = new AbortController()
    abortRef.current = controller
    try {
      await api.regenerateMessageStream(msgId, {
        onChunk: (chunk) => {
          setActive((c) => ({
            ...c,
            messages: c.messages.map((m) =>
              m.id === 'pending-regen' ? { ...m, content: (m.content || '') + chunk } : m,
            ),
          }))
        },
        onDone: async (obj) => {
          // Refetch the convo so message ids and counts are consistent.
          try {
            const fresh = await api.getConversation(active.id)
            setActive(fresh)
            setConversations((prev) => prev.map((c) =>
              c.id === fresh.id ? { ...c, ...obj.conversation } : c,
            ))
          } catch {}
        },
        onError: (msg) => {
          setError(msg)
          setActive((c) => ({
            ...c,
            messages: c.messages.filter((m) => m.id !== 'pending-regen'),
          }))
        },
        onAbort: async () => {
          await new Promise((r) => setTimeout(r, 400))
          try {
            const fresh = await api.getConversation(active.id)
            setActive(fresh)
          } catch { /* keep optimistic state */ }
        },
      }, controller.signal)
    } finally {
      abortRef.current = null
      setSending(false)
    }
  }

  async function handleSwitchModel(modelId) {
    if (!active) {
      setDefaultModel(modelId)
      return true
    }
    try {
      const updated = await api.switchModel(active.id, modelId)
      setActive((c) => ({ ...c, model_id: updated.model_id }))
      setConversations((prev) => prev.map((c) => (c.id === updated.id ? { ...c, model_id: updated.model_id } : c)))
      setError(null)
      return true
    } catch (e) {
      setError(e.message)
      return false
    }
  }

  async function handleLogout() {
    clearAttachmentWork()
    try {
      await api.logout()
    } catch {}
    setUser(null)
    setConversations([])
    setConversationCounts({ active: 0, archived: 0 })
    setConversationNextCursor(null)
    setConversationLoadingMore(false)
    setConversationView('active')
    setConversationMenuId(null)
    setConversationNotice(null)
    setActive(null)
    setActiveId(null)
    setImageGallery([])
    setImageGalleryNextCursor(null)
    setImageGalleryLoadingMore(false)
    setLoadingEarlierMessages(false)
    setSidebarOpen(false)
  }

  function selectConversation(id) {
    if (sending) return
    setLoadingEarlierMessages(false)
    chatScrollRestoreRef.current = null
    setActiveId(id)
    setMode('chat')
    setSidebarOpen(false)
  }

  function onKeyDown(e) {
    if (e.key === 'Enter' && !e.shiftKey && !e.nativeEvent.isComposing) {
      e.preventDefault()
      handleSend(e)
    }
  }

  if (!authChecked) {
    return <div className="boot-splash">Loading…</div>
  }

  if (bootError && !user) {
    return (
      <div style={{ padding: 40, color: 'var(--danger)' }}>
        <h2>Could not connect to API</h2>
        <pre>{bootError}</pre>
      </div>
    )
  }

  if (!user) {
    return (
      <AuthScreen
        registrationMode={registrationMode}
        onLoggedIn={(u) => { setUser(u); setBootError(null) }}
      />
    )
  }

  return (
    <div className={`app ${sidebarOpen ? 'sidebar-open' : ''}`}>
      {sidebarOpen && <div className="sidebar-backdrop" onClick={() => setSidebarOpen(false)} />}

      <aside className="sidebar" id="conversation-sidebar" ref={sidebarRef} aria-label="Conversations">
        <div className="sidebar-header">
          <div className="brand-mark">N</div>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div className="brand-text">AI Chat Hub</div>
            <div className="brand-sub">{models.length} models</div>
          </div>
          <button className="icon sidebar-close" onClick={() => setSidebarOpen(false)} title="Close">×</button>
        </div>

        <button className="new-chat" disabled={sending || !defaultModel} onClick={() => startNewChat()}>+ New chat</button>

        <input
          className="convo-search"
          type="search"
          aria-label="Search conversations"
          placeholder={`Search ${conversationView}…`}
          maxLength={200}
          value={search}
          onChange={(e) => {
            setSearch(e.target.value)
            setConversationNextCursor(null)
            setConversationLoadingMore(false)
          }}
        />

        <div className="convo-filters" role="group" aria-label="Conversation folders">
          <button
            type="button"
            aria-pressed={conversationView === 'active'}
            className={conversationView === 'active' ? 'selected' : ''}
            onClick={() => showConversationView('active')}
          >
            Active <span>{conversationCounts.active}</span>
          </button>
          <button
            type="button"
            aria-pressed={conversationView === 'archived'}
            className={conversationView === 'archived' ? 'selected' : ''}
            onClick={() => showConversationView('archived')}
          >
            Archived <span>{conversationCounts.archived}</span>
          </button>
        </div>

        {conversationNotice && <div className="convo-notice" role="status">{conversationNotice}</div>}

        <div className="convo-list">
          {conversations.length === 0 ? (
            <div className="empty-list">
              {search.trim()
                ? <>No {conversationView} results for “{search.trim()}”.</>
                : conversationView === 'archived'
                  ? <>No archived conversations.</>
                  : <>No conversations yet.<br/>Start one above.</>}
            </div>
          ) : (
            <>
            {conversations.map((c) => (
              <div
                key={c.id}
                className={`convo-item ${c.id === activeId ? 'active' : ''} ${c.is_pinned ? 'pinned' : ''}`}
                data-conversation-menu
                role="group"
                aria-label={c.title || 'Untitled conversation'}
              >
                <button className="convo-open" disabled={sending} aria-current={c.id === activeId ? 'page' : undefined} onClick={() => selectConversation(c.id)}>
                  <div className="convo-title">
                    {c.is_pinned && <span className="pin-mark" title="Pinned" aria-label="Pinned">●</span>}
                    {c.title || 'Untitled'}
                  </div>
                  <div className="convo-meta">{(c.model_id || '').split('/').pop()} · {c.message_count} msg</div>
                </button>
                <button
                  className="icon convo-action-toggle"
                  title="Conversation actions"
                  aria-label="Conversation actions"
                  aria-expanded={conversationMenuId === c.id}
                  disabled={sending}
                  onClick={(ev) => {
                    ev.stopPropagation()
                    conversationMenuButtonRef.current = ev.currentTarget
                    setConversationMenuId((current) => current === c.id ? null : c.id)
                  }}
                >•••</button>
                {conversationMenuId === c.id && (
                  <div className="convo-action-panel" role="group" aria-label={`Actions for ${c.title || 'Untitled'}`}>
                    {!c.archived_at && (
                      <button type="button" onClick={(ev) => handlePin(c, ev)}>
                        {c.is_pinned ? 'Unpin' : 'Pin'}
                      </button>
                    )}
                    <button type="button" onClick={(ev) => { setConversationMenuId(null); handleRename(c, ev) }}>
                      Rename
                    </button>
                    <button type="button" onClick={(ev) => handleArchive(c, ev)}>
                      {c.archived_at ? 'Restore' : 'Archive'}
                    </button>
                    <button type="button" className="danger" onClick={(ev) => handleDelete(c, ev)}>
                      Delete
                    </button>
                  </div>
                )}
              </div>
            ))}
            {conversationNextCursor && (
              <button
                type="button"
                className="convo-load-more"
                disabled={conversationLoadingMore}
                onClick={loadMoreConversations}
              >
                {conversationLoadingMore ? 'Loading…' : 'Load more conversations'}
              </button>
            )}
            </>
          )}
        </div>

        <div className="sidebar-footer">
          <div className="user-pill">
            <div className="user-avatar">{(user.username || '?')[0].toUpperCase()}</div>
            <div className="user-name">{user.username}</div>
            <button className="icon" title="Settings" onClick={() => { setMode('settings'); setSidebarOpen(false) }}>⚙</button>
            <button className="icon logout" title="Sign out" onClick={handleLogout}>⎋</button>
          </div>
        </div>
      </aside>

      <main className="main" inert={sidebarOpen ? true : undefined}>
        {mode === 'settings' && (
          <Suspense fallback={<div className="empty-list">Loading settings…</div>}>
            <Settings theme={theme} onThemeChange={setTheme} onClose={() => setMode('chat')} onLoggedOut={() => { setMode('chat'); handleLogout() }} />
          </Suspense>
        )}
        {mode !== 'settings' && (
        <>
        <div className="topbar">
          <button className="icon menu-btn" ref={menuRef} onClick={() => setSidebarOpen(true)} title="Menu" aria-label="Open conversations" aria-expanded={sidebarOpen} aria-controls="conversation-sidebar">☰</button>
          <div className="mode-toggle" role="group" aria-label="Workspace mode">
            <button
              type="button"
              className={mode === 'chat' ? 'active' : ''}
              onClick={() => setMode('chat')}
            >Chat</button>
            <button
              type="button"
              className={mode === 'image' ? 'active' : ''}
              onClick={() => setMode('image')}
              disabled={imageModels.length === 0}
            >Image</button>
          </div>
          <div className="title">
            {mode === 'chat' ? (active?.title || 'New conversation') : 'Image generation'}
          </div>
          {mode === 'chat' && active && (
            <>
              <button
                className={`icon ${showConvoSettings ? 'active' : ''}`}
                type="button"
                onClick={() => setShowConvoSettings((v) => !v)}
                title="Conversation settings (system prompt, temperature, max tokens)"
                style={{ marginRight: 2 }}
              >🎛</button>
              <a
                className="icon"
                href={api.exportConversationUrl(active.id)}
                title="Download conversation as Markdown"
                style={{ marginRight: 6 }}
              >⬇</a>
            </>
          )}
          <div className="model-select-controls">
            <div className="model-select-wrap">
              {mode === 'chat' ? (
                <select
                  value={currentModelId}
                  aria-label="Chat model"
                  aria-describedby={currentModel ? 'model-capability-summary' : undefined}
                  onChange={(e) => handleSwitchModel(e.target.value)}
                  disabled={sending}
                  title={modelLabel}
                >
                  {activeModelUnavailable && (
                    <option value={active.model_id} disabled>
                      Unavailable · {active.model_id.split('/').pop()}
                    </option>
                  )}
                  {groupedModels.map((group) => (
                    <optgroup key={group.purpose} label={group.label}>
                      {group.models.map((model) => (
                        <option key={model.id} value={model.id}>
                          {model.name}{model.vision ? ' · Vision' : ''} · {model.vendor}
                        </option>
                      ))}
                    </optgroup>
                  ))}
                </select>
              ) : (
                <select
                  value={imageModel}
                  aria-label="Image model"
                  onChange={(e) => handleSwitchImageModel(e.target.value)}
                  disabled={imageBusy}
                >
                  {imageModels.map((m) => (
                    <option key={m.id} value={m.id}>{m.name} · {m.vendor}</option>
                  ))}
                </select>
              )}
            </div>
            {mode === 'chat' && (
              <ModelExplorer
                models={models}
                currentModelId={currentModelId}
                availabilityCheckedAt={availabilityCheckedAt}
                disabled={sending}
                onSelect={handleSwitchModel}
              />
            )}
          </div>
        </div>

        {mode === 'chat' && (<>
        {currentModel && (
          <div className="model-summary" id="model-capability-summary" aria-live="polite">
            <span className="model-badge purpose">{PURPOSE_LABELS[currentModel.purpose] || 'Assistant'}</span>
            <span className="model-badge">{formatContext(currentModel.context)}</span>
            <span className={`model-badge ${supportsVision ? 'positive' : ''}`}>
              {supportsVision ? `Images · max ${currentCapabilities.max_images}` : 'No image input'}
            </span>
            <span className="model-badge positive">PDF · DOCX · TXT · MD</span>
            {currentModel.performance && (
              <span
                className={`model-badge speed-${currentModel.performance.latency_band}`}
                title="One synthetic 1-token availability probe; not a quality benchmark"
              >{formatProbeLatency(currentModel.performance)}</span>
            )}
            <span className="model-description">
              <strong>Best for:</strong> {currentModel.best_for || 'General use'} · {currentModel.description}
            </span>
          </div>
        )}
        {active && showConvoSettings && (
          <ConvoSettingsPanel
            key={active.id}
            convo={active}
            onClose={() => setShowConvoSettings(false)}
            onSaved={(updated) => {
              setActive((c) => (c ? {
                ...c,
                system_prompt: updated.system_prompt,
                temperature: updated.temperature,
                max_tokens: updated.max_tokens,
              } : c))
              setShowConvoSettings(false)
            }}
          />
        )}
        {activeModelUnavailable && (
          <div className="model-status-banner" role="alert">
            <div>
              <strong>This conversation's model is no longer available.</strong>
              <span> Choose another model before sending or regenerating.</span>
            </div>
            {defaultModelSpec && (
              <button type="button" className="primary" onClick={() => handleSwitchModel(defaultModel)}>
                Use {defaultModelSpec.name}
              </button>
            )}
          </div>
        )}
        {historicalImagesOmitted && !activeModelUnavailable && (
          <div className="model-status-banner history-media-notice" role="status">
            Earlier images remain in this conversation, but this model does not accept them.
            Text and extracted document content will still be included.
          </div>
        )}
        <div className="chat-area" ref={chatAreaRef}>
          {!active || (active.messages?.length || 0) === 0 ? (
            <div className="welcome">
              <h1>Talk to NVIDIA's <span className="accent">open models</span></h1>
              <p>Choose a model and start a conversation. Your history is private to your account.</p>
              <div className="suggestions">
                {SUGGESTIONS.map((s, i) => (
                  <button key={i} className="suggestion" onClick={() => setDraft(s)}>
                    {s}
                  </button>
                ))}
              </div>
            </div>
          ) : (
            <div className="chat-inner">
              {active.message_page?.older_cursor && (
                <button
                  type="button"
                  className="load-earlier-messages"
                  disabled={loadingEarlierMessages}
                  onClick={loadEarlierMessages}
                >
                  {loadingEarlierMessages
                    ? 'Loading earlier messages…'
                    : `Load earlier messages · ${active.messages.length} of ${active.message_page.count}`}
                </button>
              )}
              {active.messages.map((m) => (
                <MessageRow
                  key={m.id}
                  m={m}
                  modelLabel={modelLabel}
                  busy={sending}
                  onEdit={handleEditMessage}
                  onRegenerate={handleRegenerate}
                />
              ))}
              <div ref={chatEndRef} />
            </div>
          )}
        </div>

        {error && <div className="error-banner">{error}</div>}

        <form
          className={`composer-wrap ${draggingFiles ? 'dragging-files' : ''}`}
          onSubmit={handleSend}
          onPaste={handleComposerPaste}
          onDragEnter={(event) => {
            if (event.dataTransfer?.types?.includes('Files')) {
              event.preventDefault()
              setDraggingFiles(true)
            }
          }}
          onDragOver={(event) => {
            if (event.dataTransfer?.types?.includes('Files')) event.preventDefault()
          }}
          onDragLeave={(event) => {
            if (!event.currentTarget.contains(event.relatedTarget)) setDraggingFiles(false)
          }}
          onDrop={(event) => {
            if (!event.dataTransfer?.files?.length) return
            event.preventDefault()
            queueFiles(event.dataTransfer?.files)
          }}
        >
          {draggingFiles && (
            <div className="attachment-drop-overlay" role="status">
              <strong>Drop to attach</strong>
              <span>Files are checked against {currentModel?.name || 'the selected model'}.</span>
            </div>
          )}
          {(pendingAttachments.length > 0 || uploadJobs.length > 0) && (
            <div className="pending-row">
              {pendingAttachments.map((a) => (
                <AttachmentTile
                  key={a.id}
                  att={a}
                  onRemove={removePending}
                  onToggle={toggleAttachmentInclusion}
                  onPreview={openDocumentPreview}
                  included={!excludedAttachmentSet.has(a.id)}
                  compact
                />
              ))}
              {uploadJobs.map((job) => (
                <UploadJobTile
                  key={job.key}
                  job={job}
                  onCancel={cancelUpload}
                  onRetry={retryUpload}
                  onDismiss={dismissUpload}
                />
              ))}
            </div>
          )}
          {attachmentNotice && (
            <div className="attachment-notice" role="status">{attachmentNotice}</div>
          )}
          {attachmentsBlocked && (
            <div className="vision-warn attachment-warn" role="alert">
              <span>
                {incompatiblePending.length} pending attachment{incompatiblePending.length === 1 ? '' : 's'}{' '}
                {incompatiblePending.length === 1 ? 'is' : 'are'} not compatible with {currentModel?.name}.
              </span>
              <button type="button" className="link" onClick={removeIncompatibleAttachments}>
                Remove incompatible
              </button>
            </div>
          )}
          {attachmentMenuOpen && (
            <div className="attachment-picker" id="attachment-picker" aria-label="Add attachments">
              <button
                type="button"
                className="attachment-choice"
                disabled={!supportsVision || imageLimitReached || fileLimitReached}
                onClick={() => imageInputRef.current?.click()}
              >
                <span className="attachment-choice-icon" aria-hidden="true">▧</span>
                <span>
                  <strong>Add images</strong>
                  <small>
                    {supportsVision
                      ? `${imageExtensions.map((ext) => ext.toUpperCase()).join(', ')} · max ${currentCapabilities.max_images} · ${humanSize(maxImageBytes)} each`
                      : `${currentModel?.name || 'This model'} does not accept images`}
                  </small>
                </span>
              </button>
              <button
                type="button"
                className="attachment-choice"
                disabled={fileLimitReached}
                onClick={() => documentInputRef.current?.click()}
              >
                <span className="attachment-choice-icon" aria-hidden="true">≡</span>
                <span>
                  <strong>Add documents</strong>
                  <small>PDF, DOCX, TXT, MD · extracted securely as text</small>
                </span>
              </button>
              <p>Files are private to your account and their content is sent to NVIDIA only when you send.</p>
            </div>
          )}
          <div className="composer">
            <input
              ref={imageInputRef}
              type="file"
              multiple
              accept={imageAccept}
              aria-label="Choose images"
              onChange={(event) => handlePickFiles(event, 'image')}
              style={{ display: 'none' }}
            />
            <input
              ref={documentInputRef}
              type="file"
              multiple
              accept=".pdf,.txt,.md,.docx,application/pdf,text/plain,text/markdown,application/vnd.openxmlformats-officedocument.wordprocessingml.document"
              aria-label="Choose documents"
              onChange={(event) => handlePickFiles(event, 'document')}
              style={{ display: 'none' }}
            />
            <button
              ref={attachButtonRef}
              type="button"
              className="icon attach-btn"
              onClick={() => setAttachmentMenuOpen((open) => !open)}
              title="Add images or documents"
              aria-label="Add attachments"
              aria-expanded={attachmentMenuOpen}
              aria-controls="attachment-picker"
              disabled={sending || activeModelUnavailable || !currentModel || fileLimitReached}
            >📎</button>
            <textarea
              ref={textareaRef}
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              onKeyDown={onKeyDown}
              placeholder={active ? 'Reply…' : 'Ask anything, or add a document…'}
              rows={1}
              maxLength={8000}
              aria-label="Message"
              disabled={sending || activeModelUnavailable}
            />
            {sending ? (
              <button
                type="button"
                className="primary send stop"
                onClick={() => abortRef.current?.abort()}
                title="Stop generating"
              >■</button>
            ) : (
              <button
                type="submit"
                className="primary send"
                disabled={(!draft.trim() && includedPendingAttachments.length === 0) || attachmentsBlocked
                  || activeModelUnavailable || uploadingCount > 0}
                title="Send"
              >↑</button>
            )}
          </div>
          <div className="hint">
            {draft.length > 0 && <span>{draft.length.toLocaleString()} / 8,000 · </span>}
            Enter to send · Shift+Enter for newline · {includedPendingAttachments.length} selected ·{' '}
            {pendingAttachments.length + uploadJobs.length}/{attachmentLimits.max_files_per_message} files
          </div>
          <div className="privacy-hint">Drop files or paste an image · attached content is sent to NVIDIA only when you send.</div>
        </form>
        </>)}

        {mode === 'image' && (
          <div className="image-mode">
            <form className="image-form" onSubmit={handleGenerate}>
              <label className="image-prompt-label">
                <span>Prompt</span>
                <textarea
                  value={imagePrompt}
                  onChange={(e) => setImagePrompt(e.target.value)}
                  placeholder="Describe the image you want to generate…"
                  rows={3}
                  maxLength={2000}
                  disabled={imageBusy}
                />
              </label>
              <div className="image-params">
                <label>
                  <span>Width</span>
                  {currentImageSpec?.allowed_dims ? (
                    <select
                      value={imageParams.width}
                      onChange={(e) => setImageParams((p) => ({ ...p, width: Number(e.target.value) }))}
                      disabled={imageBusy}
                    >
                      {currentImageSpec.allowed_dims.map((d) => <option key={d} value={d}>{d}</option>)}
                    </select>
                  ) : (
                    <input
                      type="number" min={256} max={1536} step={64}
                      value={imageParams.width}
                      onChange={(e) => setImageParams((p) => ({ ...p, width: Number(e.target.value) }))}
                      disabled={imageBusy}
                    />
                  )}
                </label>
                <label>
                  <span>Height</span>
                  {currentImageSpec?.allowed_dims ? (
                    <select
                      value={imageParams.height}
                      onChange={(e) => setImageParams((p) => ({ ...p, height: Number(e.target.value) }))}
                      disabled={imageBusy}
                    >
                      {currentImageSpec.allowed_dims.map((d) => <option key={d} value={d}>{d}</option>)}
                    </select>
                  ) : (
                    <input
                      type="number" min={256} max={1536} step={64}
                      value={imageParams.height}
                      onChange={(e) => setImageParams((p) => ({ ...p, height: Number(e.target.value) }))}
                      disabled={imageBusy}
                    />
                  )}
                </label>
                <label>
                  <span>Steps</span>
                  <input
                    type="number" min={1} max={currentImageSpec?.max_steps || 50}
                    value={imageParams.steps}
                    onChange={(e) => setImageParams((p) => ({ ...p, steps: Number(e.target.value) }))}
                    disabled={imageBusy}
                  />
                </label>
                <label>
                  <span>Seed</span>
                  <input
                    type="number" min={0}
                    value={imageParams.seed}
                    onChange={(e) => setImageParams((p) => ({ ...p, seed: Number(e.target.value) }))}
                    disabled={imageBusy}
                  />
                </label>
              </div>
              {error && <div className="error-banner inline">{error}</div>}
              <button
                type="submit"
                className="primary"
                disabled={!imagePrompt.trim() || imageBusy || !imageModel}
              >
                {imageBusy ? 'Generating…' : 'Generate'}
              </button>
            </form>
            <div className="gallery">
              {imageGallery.length === 0 ? (
                <div className="empty-list">No generations yet. Describe an image above.</div>
              ) : (
                imageGallery.map((a) => (
                  <a key={a.id} href={mediaUrl(a.url)} target="_blank" rel="noreferrer" className="gallery-tile">
                    <img src={mediaUrl(a.url)} alt={a.original_name} loading="lazy" />
                  </a>
                ))
              )}
            </div>
            {imageGalleryNextCursor && (
              <button
                type="button"
                className="gallery-load-more"
                disabled={imageGalleryLoadingMore}
                onClick={loadMoreGallery}
              >
                {imageGalleryLoadingMore ? 'Loading…' : 'Load more generations'}
              </button>
            )}
          </div>
        )}
        {previewAttachment && (
          <DocumentPreview attachment={previewAttachment} onClose={closeDocumentPreview} />
        )}
        </>
        )}
      </main>
    </div>
  )
}
