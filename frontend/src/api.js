const BASE = '/api'

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
    ...opts,
    credentials: 'include',
    headers,
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
    let detail
    try {
      const j = await res.clone().json()
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

export const MEDIA_BASE = ''
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
  register: (username, email, password, invite_code) =>
    request('/auth/register/', {
      method: 'POST',
      body: JSON.stringify({ username, email, password, ...(invite_code ? { invite_code } : {}) }),
    }),
  verifyCode: (email, code) =>
    request('/auth/verify/', { method: 'POST', body: JSON.stringify({ email, code }) }),
  resend: (email) =>
    request('/auth/resend/', { method: 'POST', body: JSON.stringify({ email }) }),
  forgotPassword: (email) =>
    request('/auth/forgot/', { method: 'POST', body: JSON.stringify({ email }) }),
  resetPassword: (email, code, password) =>
    request('/auth/reset/', { method: 'POST', body: JSON.stringify({ email, code, password }) }),
  listModels: () => request('/models/'),
  listConversations: (q, view = 'active', cursor = null) => {
    const params = new URLSearchParams()
    if (q) params.set('q', q)
    if (view) params.set('view', view)
    if (cursor) params.set('cursor', cursor)
    params.set('limit', '30')
    params.set('include_counts', '1')
    return request(`/conversations/?${params.toString()}`)
  },
  getConversation: (id) => request(`/conversations/${id}/?message_page=1&limit=50`),
  listEarlierMessages: (id, cursor) => {
    const params = new URLSearchParams({ limit: '50' })
    if (cursor) params.set('cursor', cursor)
    return request(`/conversations/${id}/messages/?${params.toString()}`)
  },
  createConversation: (model_id, title = 'New Chat') =>
    request('/conversations/', { method: 'POST', body: JSON.stringify({ model_id, title }) }),
  deleteConversation: (id) => request(`/conversations/${id}/`, { method: 'DELETE' }),
  renameConversation: (id, title) =>
    request(`/conversations/${id}/`, { method: 'PATCH', body: JSON.stringify({ title }) }),
  updateConversation: (id, patch) =>
    request(`/conversations/${id}/`, { method: 'PATCH', body: JSON.stringify(patch) }),
  switchModel: (id, model_id) =>
    request(`/conversations/${id}/`, { method: 'PATCH', body: JSON.stringify({ model_id }) }),
  sendMessageStream: async (id, content, model_id, attachment_ids, handlers, signal) => {
    const headers = { 'Content-Type': 'application/json' }
    const csrf = getCookie('csrftoken')
    if (csrf) headers['X-CSRFToken'] = csrf
    try {
      const res = await fetch(`${BASE}/conversations/${id}/messages/`, {
        method: 'POST',
        credentials: 'include',
        headers,
        signal,
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
    } catch (e) {
      if (e.name === 'AbortError') { handlers.onAbort?.(); return }
      throw e
    }
  },
  listAttachments: (kind, cursor = null) => {
    const params = new URLSearchParams({ include_count: '1', limit: '30' })
    if (kind) params.set('kind', kind)
    if (cursor) params.set('cursor', cursor)
    return request(`/attachments/?${params.toString()}`)
  },
  uploadAttachment: (file, modelId, { onProgress, signal } = {}) => {
    const fd = new FormData()
    fd.append('file', file)
    if (modelId) fd.append('model_id', modelId)
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest()
      let settled = false
      const finish = (callback, value) => {
        if (settled) return
        settled = true
        signal?.removeEventListener('abort', abort)
        callback(value)
      }
      const abort = () => xhr.abort()

      xhr.open('POST', `${BASE}/attachments/upload/`)
      xhr.withCredentials = true
      const csrf = getCookie('csrftoken')
      if (csrf) xhr.setRequestHeader('X-CSRFToken', csrf)
      xhr.upload.onprogress = (event) => {
        if (event.lengthComputable) onProgress?.(Math.round((event.loaded / event.total) * 100))
      }
      xhr.onload = () => {
        let body = null
        try { body = JSON.parse(xhr.responseText) } catch {}
        if (xhr.status >= 200 && xhr.status < 300) {
          finish(resolve, body)
          return
        }
        const error = new Error(body?.error || body?.detail || `HTTP ${xhr.status}`)
        error.status = xhr.status
        error.body = body
        finish(reject, error)
      }
      xhr.onerror = () => finish(reject, new Error('Upload failed. Check your connection and retry.'))
      xhr.onabort = () => finish(reject, new DOMException('Upload canceled', 'AbortError'))
      signal?.addEventListener('abort', abort, { once: true })
      if (signal?.aborted) {
        finish(reject, new DOMException('Upload canceled', 'AbortError'))
        return
      }
      xhr.send(fd)
    })
  },
  deleteAttachment: (id) => request(`/attachments/${id}/`, { method: 'DELETE' }),
  previewAttachment: (id) => request(`/attachments/${id}/preview/`),
  listImageModels: () => request('/images/models/'),
  generateImage: (params) =>
    request('/images/generate/', { method: 'POST', body: JSON.stringify(params) }),

  // Export
  exportConversationUrl: (id) => `${BASE}/conversations/${id}/export/`,

  // Edit / regenerate
  editMessage: (id, content) =>
    request(`/messages/${id}/`, { method: 'PATCH', body: JSON.stringify({ content }) }),
  regenerateMessageStream: async (id, handlers, signal) => {
    const headers = {}
    const csrf = getCookie('csrftoken')
    if (csrf) headers['X-CSRFToken'] = csrf
    try {
      const res = await fetch(`${BASE}/messages/${id}/regenerate/`, {
        method: 'POST', credentials: 'include', headers, signal,
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
    } catch (e) {
      if (e.name === 'AbortError') { handlers.onAbort?.(); return }
      throw e
    }
  },

  // 2FA
  twoFactorStatus: () => request('/auth/2fa/status/'),
  twoFactorEnroll: (password) =>
    request('/auth/2fa/enroll/', { method: 'POST', body: JSON.stringify({ password }) }),
  twoFactorVerifyEnroll: (code) =>
    request('/auth/2fa/verify-enroll/', { method: 'POST', body: JSON.stringify({ code }) }),
  twoFactorDisable: (password, code) =>
    request('/auth/2fa/disable/', { method: 'POST', body: JSON.stringify({ password, code }) }),
  twoFactorRegenRecovery: (password, code) =>
    request('/auth/2fa/recovery-codes/', {
      method: 'POST', body: JSON.stringify({ password, code }),
    }),

  // Account
  accountUsage: () => request('/account/usage/'),
  changePassword: (current_password, new_password) =>
    request('/auth/password/', { method: 'POST', body: JSON.stringify({ current_password, new_password }) }),
  deleteAccount: (password, code) =>
    request('/auth/delete-account/', { method: 'POST', body: JSON.stringify({ password, ...(code ? { code } : {}) }) }),

  // Sessions
  listSessions: () => request('/auth/sessions/'),
  revokeSession: (key) => request(`/auth/sessions/${encodeURIComponent(key)}/`, { method: 'DELETE' }),
  revokeOtherSessions: () => request('/auth/sessions/revoke-others/', { method: 'DELETE' }),
}
