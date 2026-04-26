import { useEffect, useMemo, useRef, useState } from 'react'
import ReactMarkdown from 'react-markdown'
import rehypeHighlight from 'rehype-highlight'
import remarkGfm from 'remark-gfm'
import 'highlight.js/styles/github-dark.css'
import { api, mediaUrl } from './api'

const MAX_FILE_BYTES = 10 * 1024 * 1024
const ALLOWED_EXT = ['jpg', 'jpeg', 'png', 'webp', 'gif', 'pdf', 'txt', 'md', 'docx']

function fileExt(name) {
  const i = (name || '').lastIndexOf('.')
  return i >= 0 ? name.slice(i + 1).toLowerCase() : ''
}

function humanSize(bytes) {
  if (!bytes) return '0 B'
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(0)} KB`
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`
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

function AuthScreen({ initialMode = 'login', onLoggedIn }) {
  const [mode, setMode] = useState(initialMode)
  const [username, setUsername] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const [pendingEmail, setPendingEmail] = useState('')
  const [pendingCooldown, setPendingCooldown] = useState(60)

  function switchMode(next) {
    setMode(next)
    setError(null)
    setPassword('')
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
          const u = await api.login(username, password)
          onLoggedIn(u)
        } catch (err) {
          if (err.status === 401) {
            setError('Invalid username or password. (If you just registered, verify your email first.)')
          } else {
            setError(err.message)
          }
        }
      } else {
        const r = await api.register(username, email, password)
        setPendingEmail(email)
        setPendingCooldown(r.resend_available_in || 60)
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
        onReset={onLoggedIn}
        onBack={() => switchMode('login')}
      />
    )
  }

  const isRegister = mode === 'register'

  return (
    <div className="login-wrap">
      <form className="login-card" onSubmit={submit}>
        <div className="login-brand">
          <div className="brand-mark">N</div>
          <div>
            <div className="brand-text">NVIDIA Chat Hub</div>
            <div className="brand-sub">{isRegister ? 'Create an account' : 'Sign in to continue'}</div>
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
        {error && <div className="login-error">{error}</div>}
        <button
          type="submit"
          className="primary login-submit"
          disabled={busy || !username || !password || (isRegister && !email)}
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
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        rehypePlugins={[rehypeHighlight]}
        components={{
          pre({ children, ...rest }) {
            const codeText = (() => {
              try {
                const c = Array.isArray(children) ? children[0] : children
                return c?.props?.children?.toString() || ''
              } catch { return '' }
            })()
            return (
              <div className="code-block">
                <CopyButton text={codeText} label="Copy code" />
                <pre {...rest}>{children}</pre>
              </div>
            )
          },
          a({ children, ...props }) {
            return <a {...props} target="_blank" rel="noreferrer">{children}</a>
          },
        }}
      >
        {content}
      </ReactMarkdown>
    </div>
  )
}

function AttachmentTile({ att, onRemove, compact }) {
  const isImage = att.kind === 'image' || att.kind === 'generated_image'
  const url = mediaUrl(att.url)
  if (isImage) {
    return (
      <div className={`att-tile image ${compact ? 'compact' : ''}`}>
        <a href={url} target="_blank" rel="noreferrer">
          <img src={url} alt={att.original_name} />
        </a>
        {onRemove && (
          <button type="button" className="att-remove" onClick={() => onRemove(att.id)} title="Remove">×</button>
        )}
      </div>
    )
  }
  return (
    <div className={`att-tile doc ${compact ? 'compact' : ''}`}>
      <div className="att-doc-icon">{(fileExt(att.original_name) || 'DOC').toUpperCase()}</div>
      <div className="att-doc-meta">
        <div className="att-doc-name" title={att.original_name}>{att.original_name}</div>
        <div className="att-doc-size">{humanSize(att.size)}{att.has_text ? ' · text extracted' : ''}</div>
      </div>
      {onRemove && (
        <button type="button" className="att-remove" onClick={() => onRemove(att.id)} title="Remove">×</button>
      )}
    </div>
  )
}

export default function App() {
  const [authChecked, setAuthChecked] = useState(false)
  const [user, setUser] = useState(null)
  const [models, setModels] = useState([])
  const [defaultModel, setDefaultModel] = useState('')
  const [conversations, setConversations] = useState([])
  const [activeId, setActiveId] = useState(null)
  const [active, setActive] = useState(null)
  const [draft, setDraft] = useState('')
  const [sending, setSending] = useState(false)
  const [error, setError] = useState(null)
  const [bootError, setBootError] = useState(null)
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const [mode, setMode] = useState('chat')
  const [pendingAttachments, setPendingAttachments] = useState([])
  const [uploadingCount, setUploadingCount] = useState(0)
  const [imageModels, setImageModels] = useState([])
  const [imageModel, setImageModel] = useState('')
  const [imagePrompt, setImagePrompt] = useState('')
  const [imageBusy, setImageBusy] = useState(false)
  const [imageParams, setImageParams] = useState({ width: 1024, height: 1024, steps: 4, seed: 0 })
  const [imageGallery, setImageGallery] = useState([])
  const chatEndRef = useRef(null)
  const textareaRef = useRef(null)
  const fileInputRef = useRef(null)

  useEffect(() => {
    let cancelled = false
    api.me()
      .then((u) => {
        if (cancelled) return
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
        setConversations(c)
        setImageModels(im.models || [])
        setImageModel(im.default || (im.models?.[0]?.id) || '')
        setImageGallery(gallery || [])
      })
      .catch((e) => {
        if (cancelled) return
        if (e.status === 401 || e.status === 403) { setUser(null); return }
        setBootError(e.message)
      })
    return () => { cancelled = true }
  }, [user])

  useEffect(() => {
    if (!activeId) { setActive(null); return }
    let cancelled = false
    api.getConversation(activeId)
      .then((c) => !cancelled && setActive(c))
      .catch((e) => !cancelled && setError(e.message))
    return () => { cancelled = true }
  }, [activeId])

  useEffect(() => {
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

  const modelLabel = currentModel ? `${currentModel.name} · ${currentModel.vendor}` : currentModelId
  const supportsVision = !!currentModel?.vision

  const hasPendingImages = pendingAttachments.some((a) => a.kind === 'image')
  const imageBlocked = hasPendingImages && !supportsVision

  const currentImageSpec = useMemo(
    () => imageModels.find((m) => m.id === imageModel),
    [imageModels, imageModel],
  )

  async function startNewChat(modelId = defaultModel) {
    try {
      const c = await api.createConversation(modelId)
      setConversations((prev) => [c, ...prev])
      setActiveId(c.id)
      setActive(c)
      setError(null)
      setSidebarOpen(false)
    } catch (e) {
      setError(e.message)
    }
  }

  async function handlePickFiles(e) {
    const files = Array.from(e.target.files || [])
    e.target.value = ''
    if (!files.length) return
    setError(null)
    for (const f of files) {
      const ext = fileExt(f.name)
      if (!ALLOWED_EXT.includes(ext)) {
        setError(`Unsupported file type: .${ext}. Allowed: ${ALLOWED_EXT.join(', ')}`)
        continue
      }
      if (f.size > MAX_FILE_BYTES) {
        setError(`${f.name} is larger than 10 MB.`)
        continue
      }
      setUploadingCount((n) => n + 1)
      try {
        const att = await api.uploadAttachment(f)
        setPendingAttachments((prev) => [...prev, att])
      } catch (err) {
        setError(err.message)
      } finally {
        setUploadingCount((n) => n - 1)
      }
    }
  }

  async function removePending(id) {
    try { await api.deleteAttachment(id) } catch {}
    setPendingAttachments((prev) => prev.filter((a) => a.id !== id))
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

  async function handleSend(e) {
    e?.preventDefault?.()
    const text = draft.trim()
    if (sending || imageBlocked) return
    if (!text && pendingAttachments.length === 0) return

    let convo = active
    if (!convo) {
      try {
        convo = await api.createConversation(currentModelId || defaultModel)
        setConversations((prev) => [convo, ...prev])
        setActiveId(convo.id)
        setActive(convo)
      } catch (err) { setError(err.message); return }
    }

    setError(null)
    setSending(true)
    setDraft('')

    const sendingAttachments = pendingAttachments
    setPendingAttachments([])

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
        }))
        setConversations((prev) => {
          const others = prev.filter((p) => p.id !== convo.id)
          return [final.conversation, ...others]
        })
      },
      onError: (msg) => {
        setError(msg)
        setPendingAttachments(sendingAttachments)
        setActive((c) => ({
          ...c,
          messages: (c?.messages || []).filter(
            (m) => m.id !== tmpUserId && m.id !== streamingId,
          ),
        }))
      },
    })

    setSending(false)
  }

  async function handleDelete(id, ev) {
    ev?.stopPropagation?.()
    if (!confirm('Delete this conversation?')) return
    try {
      await api.deleteConversation(id)
      setConversations((prev) => prev.filter((c) => c.id !== id))
      if (activeId === id) { setActiveId(null); setActive(null) }
    } catch (e) { setError(e.message) }
  }

  async function handleSwitchModel(modelId) {
    if (!active) {
      setDefaultModel(modelId)
      return
    }
    try {
      const updated = await api.switchModel(active.id, modelId)
      setActive((c) => ({ ...c, model_id: updated.model_id }))
      setConversations((prev) => prev.map((c) => (c.id === updated.id ? { ...c, model_id: updated.model_id } : c)))
    } catch (e) { setError(e.message) }
  }

  async function handleLogout() {
    try {
      await api.logout()
    } catch {}
    setUser(null)
    setConversations([])
    setActive(null)
    setActiveId(null)
    setSidebarOpen(false)
  }

  function selectConversation(id) {
    setActiveId(id)
    setSidebarOpen(false)
  }

  function onKeyDown(e) {
    if (e.key === 'Enter' && !e.shiftKey) {
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
    return <AuthScreen onLoggedIn={(u) => { setUser(u); setBootError(null) }} />
  }

  return (
    <div className={`app ${sidebarOpen ? 'sidebar-open' : ''}`}>
      {sidebarOpen && <div className="sidebar-backdrop" onClick={() => setSidebarOpen(false)} />}

      <aside className="sidebar">
        <div className="sidebar-header">
          <div className="brand-mark">N</div>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div className="brand-text">NVIDIA Chat Hub</div>
            <div className="brand-sub">{models.length} models</div>
          </div>
          <button className="icon sidebar-close" onClick={() => setSidebarOpen(false)} title="Close">×</button>
        </div>

        <button className="new-chat" onClick={() => startNewChat()}>+ New chat</button>

        <div className="convo-list">
          {conversations.length === 0 ? (
            <div className="empty-list">No conversations yet.<br/>Start one below.</div>
          ) : (
            conversations.map((c) => (
              <div
                key={c.id}
                className={`convo-item ${c.id === activeId ? 'active' : ''}`}
                onClick={() => selectConversation(c.id)}
              >
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div className="convo-title">{c.title || 'Untitled'}</div>
                  <div className="convo-meta">{(c.model_id || '').split('/').pop()} · {c.message_count} msg</div>
                </div>
                <button
                  className="icon danger delete"
                  title="Delete"
                  onClick={(ev) => handleDelete(c.id, ev)}
                >×</button>
              </div>
            ))
          )}
        </div>

        <div className="sidebar-footer">
          <div className="user-pill">
            <div className="user-avatar">{(user.username || '?')[0].toUpperCase()}</div>
            <div className="user-name">{user.username}</div>
            <button className="icon logout" title="Sign out" onClick={handleLogout}>⎋</button>
          </div>
        </div>
      </aside>

      <main className="main">
        <div className="topbar">
          <button className="icon menu-btn" onClick={() => setSidebarOpen(true)} title="Menu">☰</button>
          <div className="mode-toggle" role="tablist">
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
          <div className="model-select-wrap">
            {mode === 'chat' ? (
              <select
                value={currentModelId}
                onChange={(e) => handleSwitchModel(e.target.value)}
                disabled={sending}
                title={modelLabel}
              >
                {models.map((m) => (
                  <option key={m.id} value={m.id}>
                    {m.name}{m.vision ? ' · 👁' : ''} · {m.vendor}
                  </option>
                ))}
              </select>
            ) : (
              <select
                value={imageModel}
                onChange={(e) => setImageModel(e.target.value)}
                disabled={imageBusy}
              >
                {imageModels.map((m) => (
                  <option key={m.id} value={m.id}>{m.name} · {m.vendor}</option>
                ))}
              </select>
            )}
          </div>
        </div>

        {mode === 'chat' && (<>
        <div className="chat-area">
          {!active || (active.messages?.length || 0) === 0 ? (
            <div className="welcome">
              <h1>Talk to NVIDIA's <span className="accent">open models</span></h1>
              <p>Pick a model up top, type below, hit enter. All conversations are saved on this server.</p>
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
              {active.messages.map((m) => (
                <div key={m.id} className={`msg ${m.role}`}>
                  <div className="avatar">{m.role === 'user' ? 'U' : 'AI'}</div>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div className="role">
                      <span>{m.role === 'user' ? 'You' : modelLabel}</span>
                      {m.role === 'assistant' && m.content && (
                        <CopyButton text={m.content} />
                      )}
                    </div>
                    {(m.attachments || []).length > 0 && (
                      <div className="msg-attachments">
                        {m.attachments.map((a) => <AttachmentTile key={a.id} att={a} />)}
                      </div>
                    )}
                    {m.streaming && !m.content ? (
                      <div className="bubble assistant-bubble">
                        <span className="typing"><span/><span/><span/></span>
                      </div>
                    ) : m.content ? (
                      <MessageBody role={m.role} content={m.content} />
                    ) : null}
                  </div>
                </div>
              ))}
              <div ref={chatEndRef} />
            </div>
          )}
        </div>

        {error && <div className="error-banner">{error}</div>}

        <form className="composer-wrap" onSubmit={handleSend}>
          {(pendingAttachments.length > 0 || uploadingCount > 0) && (
            <div className="pending-row">
              {pendingAttachments.map((a) => (
                <AttachmentTile key={a.id} att={a} onRemove={removePending} compact />
              ))}
              {uploadingCount > 0 && (
                <div className="att-tile uploading">Uploading…</div>
              )}
            </div>
          )}
          {imageBlocked && (
            <div className="vision-warn">
              The selected model can't read images. Pick a vision model (look for 👁) or remove the images.
            </div>
          )}
          <div className="composer">
            <input
              ref={fileInputRef}
              type="file"
              multiple
              accept=".jpg,.jpeg,.png,.webp,.gif,.pdf,.txt,.md,.docx,image/*,application/pdf,text/plain,text/markdown"
              onChange={handlePickFiles}
              style={{ display: 'none' }}
            />
            <button
              type="button"
              className="icon attach-btn"
              onClick={() => fileInputRef.current?.click()}
              title="Attach files (images, PDF, txt, md, docx)"
              disabled={sending}
            >📎</button>
            <textarea
              ref={textareaRef}
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              onKeyDown={onKeyDown}
              placeholder={active ? 'Reply…' : 'Ask anything, or attach a file…'}
              rows={1}
              disabled={sending}
            />
            <button
              type="submit"
              className="primary send"
              disabled={(!draft.trim() && pendingAttachments.length === 0) || sending || imageBlocked || uploadingCount > 0}
              title="Send"
            >
              {sending ? '…' : '↑'}
            </button>
          </div>
          <div className="hint">Enter to send · Shift+Enter for newline · Powered by NVIDIA NIM API</div>
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
                  <input
                    type="number" min={256} max={1536} step={64}
                    value={imageParams.width}
                    onChange={(e) => setImageParams((p) => ({ ...p, width: Number(e.target.value) }))}
                    disabled={imageBusy}
                  />
                </label>
                <label>
                  <span>Height</span>
                  <input
                    type="number" min={256} max={1536} step={64}
                    value={imageParams.height}
                    onChange={(e) => setImageParams((p) => ({ ...p, height: Number(e.target.value) }))}
                    disabled={imageBusy}
                  />
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
          </div>
        )}
      </main>
    </div>
  )
}
