const BASE = import.meta.env.DEV ? 'http://127.0.0.1:8500/api' : '/api'

function getCookie(name) {
  const m = document.cookie.match(new RegExp('(?:^|; )' + name + '=([^;]*)'))
  return m ? decodeURIComponent(m[1]) : null
}

async function request(path, opts = {}) {
  const method = (opts.method || 'GET').toUpperCase()
  const isForm = opts.body instanceof FormData
  const headers = { ...(opts.headers || {}) }
  if (!isForm && opts.body && !headers['Content-Type']) {
    headers['Content-Type'] = 'application/json'
  }
  if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
    const csrf = getCookie('csrftoken')
    if (csrf) headers['X-CSRFToken'] = csrf
  }
  const res = await fetch(`${BASE}${path}`, {
    credentials: 'include',
    headers,
    ...opts,
  })
  if (res.status === 401 || res.status === 403) {
    let body = null
    try { body = await res.json() } catch {}
    const err = new Error(body?.error || 'Unauthorized')
    err.status = res.status
    err.body = body
    throw err
  }
  if (!res.ok) {
    let detail = ''
    try {
      const j = await res.json()
      detail = j.error || j.detail || JSON.stringify(j)
    } catch {
      detail = await res.text()
    }
    const err = new Error(detail || `HTTP ${res.status}`)
    err.status = res.status
    throw err
  }
  if (res.status === 204) return null
  return res.json()
}

export const MEDIA_BASE = import.meta.env.DEV ? 'http://127.0.0.1:8500' : ''
export function mediaUrl(url) {
  if (!url) return ''
  if (url.startsWith('http')) return url
  return MEDIA_BASE + url
}

export const api = {
  me: () => request('/auth/me/'),
  login: (username, password, code) =>
    request('/auth/login/', { method: 'POST', body: JSON.stringify({ username, password, ...(code ? { code } : {}) }) }),
  logout: () => request('/auth/logout/', { method: 'POST' }),
  register: (username, email, password) =>
    request('/auth/register/', { method: 'POST', body: JSON.stringify({ username, email, password }) }),
  verifyCode: (email, code) =>
    request('/auth/verify/', { method: 'POST', body: JSON.stringify({ email, code }) }),
  resend: (email) =>
    request('/auth/resend/', { method: 'POST', body: JSON.stringify({ email }) }),
  forgotPassword: (email) =>
    request('/auth/forgot/', { method: 'POST', body: JSON.stringify({ email }) }),
  resetPassword: (email, code, password) =>
    request('/auth/reset/', { method: 'POST', body: JSON.stringify({ email, code, password }) }),
  listModels: () => request('/models/'),
  listConversations: () => request('/conversations/'),
  getConversation: (id) => request(`/conversations/${id}/`),
  createConversation: (model_id, title = 'New Chat') =>
    request('/conversations/', { method: 'POST', body: JSON.stringify({ model_id, title }) }),
  deleteConversation: (id) => request(`/conversations/${id}/`, { method: 'DELETE' }),
  renameConversation: (id, title) =>
    request(`/conversations/${id}/`, { method: 'PATCH', body: JSON.stringify({ title }) }),
  switchModel: (id, model_id) =>
    request(`/conversations/${id}/`, { method: 'PATCH', body: JSON.stringify({ model_id }) }),
  sendMessageStream: async (id, content, model_id, attachment_ids, handlers) => {
    const headers = { 'Content-Type': 'application/json' }
    const csrf = getCookie('csrftoken')
    if (csrf) headers['X-CSRFToken'] = csrf
    const res = await fetch(`${BASE}/conversations/${id}/messages/`, {
      method: 'POST',
      credentials: 'include',
      headers,
      body: JSON.stringify({
        content,
        ...(model_id ? { model_id } : {}),
        ...(attachment_ids && attachment_ids.length ? { attachment_ids } : {}),
      }),
    })
    if (!res.ok) {
      let detail = `HTTP ${res.status}`
      try { const j = await res.json(); detail = j.error || j.detail || detail } catch {}
      handlers.onError?.(detail, res.status)
      return
    }
    const reader = res.body.getReader()
    const decoder = new TextDecoder()
    let buffer = ''
    while (true) {
      const { value, done } = await reader.read()
      if (done) break
      buffer += decoder.decode(value, { stream: true })
      let idx
      while ((idx = buffer.indexOf('\n\n')) !== -1) {
        const event = buffer.slice(0, idx).trim()
        buffer = buffer.slice(idx + 2)
        if (!event.startsWith('data:')) continue
        try {
          const obj = JSON.parse(event.slice(5).trim())
          if (obj.error) { handlers.onError?.(obj.error); return }
          if (obj.done) { handlers.onDone?.(obj); return }
          if (obj.chunk) handlers.onChunk?.(obj.chunk)
          if (obj.user_message) handlers.onUserMessage?.(obj.user_message)
        } catch { /* skip malformed event */ }
      }
    }
  },
  listAttachments: (kind) => request(`/attachments/${kind ? `?kind=${encodeURIComponent(kind)}` : ''}`),
  uploadAttachment: (file) => {
    const fd = new FormData()
    fd.append('file', file)
    return request('/attachments/upload/', { method: 'POST', body: fd })
  },
  deleteAttachment: (id) => request(`/attachments/${id}/`, { method: 'DELETE' }),
  listImageModels: () => request('/images/models/'),
  generateImage: (params) =>
    request('/images/generate/', { method: 'POST', body: JSON.stringify(params) }),

  // Export
  exportConversationUrl: (id) => `${BASE}/conversations/${id}/export/`,

  // Edit / regenerate
  editMessage: (id, content) =>
    request(`/messages/${id}/`, { method: 'PATCH', body: JSON.stringify({ content }) }),
  regenerateMessageStream: async (id, handlers) => {
    const headers = {}
    const csrf = getCookie('csrftoken')
    if (csrf) headers['X-CSRFToken'] = csrf
    const res = await fetch(`${BASE}/messages/${id}/regenerate/`, {
      method: 'POST', credentials: 'include', headers,
    })
    if (!res.ok) {
      let detail = `HTTP ${res.status}`
      try { const j = await res.json(); detail = j.error || j.detail || detail } catch {}
      handlers.onError?.(detail, res.status); return
    }
    const reader = res.body.getReader()
    const decoder = new TextDecoder()
    let buffer = ''
    while (true) {
      const { value, done } = await reader.read()
      if (done) break
      buffer += decoder.decode(value, { stream: true })
      let idx
      while ((idx = buffer.indexOf('\n\n')) !== -1) {
        const event = buffer.slice(0, idx).trim()
        buffer = buffer.slice(idx + 2)
        if (!event.startsWith('data:')) continue
        try {
          const obj = JSON.parse(event.slice(5).trim())
          if (obj.error) { handlers.onError?.(obj.error); return }
          if (obj.done) { handlers.onDone?.(obj); return }
          if (obj.chunk) handlers.onChunk?.(obj.chunk)
        } catch { /* skip malformed */ }
      }
    }
  },

  // 2FA
  twoFactorStatus: () => request('/auth/2fa/status/'),
  twoFactorEnroll: () => request('/auth/2fa/enroll/', { method: 'POST' }),
  twoFactorVerifyEnroll: (code) =>
    request('/auth/2fa/verify-enroll/', { method: 'POST', body: JSON.stringify({ code }) }),
  twoFactorDisable: (password, code) =>
    request('/auth/2fa/disable/', { method: 'POST', body: JSON.stringify({ password, code }) }),
  twoFactorRegenRecovery: (code) =>
    request('/auth/2fa/recovery-codes/', { method: 'POST', body: JSON.stringify({ code }) }),

  // Sessions
  listSessions: () => request('/auth/sessions/'),
  revokeSession: (key) => request(`/auth/sessions/${encodeURIComponent(key)}/`, { method: 'DELETE' }),
  revokeOtherSessions: () => request('/auth/sessions/revoke-others/', { method: 'DELETE' }),
}
