import { useEffect, useMemo, useRef, useState } from 'react'
import { api } from './api'

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
  const chatEndRef = useRef(null)
  const textareaRef = useRef(null)

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
    Promise.all([api.listModels(), api.listConversations()])
      .then(([m, c]) => {
        if (cancelled) return
        setModels(m.models)
        setDefaultModel(m.default)
        setConversations(c)
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

  const modelLabel = useMemo(() => {
    const m = models.find((x) => x.id === currentModelId)
    return m ? `${m.name} · ${m.vendor}` : currentModelId
  }, [models, currentModelId])

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

  async function handleSend(e) {
    e?.preventDefault?.()
    const text = draft.trim()
    if (!text || sending) return

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

    setActive((c) => ({
      ...c,
      messages: [...(c?.messages || []), { id: `tmp-${Date.now()}`, role: 'user', content: text }],
    }))

    try {
      const res = await api.sendMessage(convo.id, text)
      setActive((c) => {
        const base = c?.messages?.filter((m) => !String(m.id).startsWith('tmp-')) || []
        return {
          ...c,
          messages: [...base, res.user_message, res.assistant_message],
        }
      })
      setConversations((prev) => {
        const others = prev.filter((p) => p.id !== convo.id)
        return [res.conversation, ...others]
      })
    } catch (err) {
      setError(err.message)
      setActive((c) => ({
        ...c,
        messages: (c?.messages || []).filter((m) => !String(m.id).startsWith('tmp-')),
      }))
    } finally {
      setSending(false)
    }
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
          <div className="title">{active?.title || 'New conversation'}</div>
          <div className="model-select-wrap">
            <select
              value={currentModelId}
              onChange={(e) => handleSwitchModel(e.target.value)}
              disabled={sending}
              title={modelLabel}
            >
              {models.map((m) => (
                <option key={m.id} value={m.id}>
                  {m.name} · {m.vendor}
                </option>
              ))}
            </select>
          </div>
        </div>

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
                    <div className="role">{m.role === 'user' ? 'You' : modelLabel}</div>
                    <div className="bubble">{m.content}</div>
                  </div>
                </div>
              ))}
              {sending && (
                <div className="msg assistant">
                  <div className="avatar">AI</div>
                  <div style={{ flex: 1 }}>
                    <div className="role">{modelLabel}</div>
                    <div className="bubble">
                      <span className="typing"><span/><span/><span/></span>
                    </div>
                  </div>
                </div>
              )}
              <div ref={chatEndRef} />
            </div>
          )}
        </div>

        {error && <div className="error-banner">{error}</div>}

        <form className="composer-wrap" onSubmit={handleSend}>
          <div className="composer">
            <textarea
              ref={textareaRef}
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              onKeyDown={onKeyDown}
              placeholder={active ? 'Reply…' : 'Ask anything…'}
              rows={1}
              disabled={sending}
            />
            <button type="submit" className="primary send" disabled={!draft.trim() || sending} title="Send">
              {sending ? '…' : '↑'}
            </button>
          </div>
          <div className="hint">Enter to send · Shift+Enter for newline · Powered by NVIDIA NIM API</div>
        </form>
      </main>
    </div>
  )
}
