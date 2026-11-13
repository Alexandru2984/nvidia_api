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
    let body = null
    try {
      body = await res.clone().json()
      detail = body.error || body.detail || JSON.stringify(body)
    } catch {
      detail = await res.text()
    }
    const err = new Error(detail || `HTTP ${res.status}`)
    err.status = res.status
    err.body = body
    throw err
  }
  if (res.status === 204) return null
  return res.json()
}

const MAX_STREAM_BYTES = 3 * 1024 * 1024
const MAX_STREAM_EVENT_CHARS = 1024 * 1024
const STREAM_PROTOCOL_ERROR = 'The response stream was invalid. Try again later.'
const STREAM_CONNECTION_ERROR = 'The response stream ended unexpectedly. Try again.'

async function consumeEventStream(res, handlers) {
  const contentType = (res.headers.get('Content-Type') || '').split(';', 1)[0].trim().toLowerCase()
  if (contentType !== 'text/event-stream' || !res.body) {
    handlers.onError?.(STREAM_PROTOCOL_ERROR)
    return
  }

  const reader = res.body.getReader()
  const decoder = new TextDecoder('utf-8', { fatal: true })
  let buffer = ''
  let scanOffset = 0
  let dataLines = []
  let eventCharacters = 0
  let streamBytes = 0
  let stopped = false

  const fail = (message = STREAM_PROTOCOL_ERROR) => {
    if (!stopped) handlers.onError?.(message)
    stopped = true
    return true
  }

  const dispatch = () => {
    if (!dataLines.length) return false
    const raw = dataLines.join('\n')
    dataLines = []
    eventCharacters = 0
    let obj
    try {
      obj = JSON.parse(raw)
    } catch {
      return fail()
    }
    if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return fail()
    if (obj.error) {
      handlers.onError?.(typeof obj.error === 'string' ? obj.error : STREAM_PROTOCOL_ERROR)
      stopped = true
      return true
    }
    if (obj.done === true) {
      handlers.onDone?.(obj)
      stopped = true
      return true
    }
    if (obj.chunk !== undefined) {
      if (typeof obj.chunk !== 'string') return fail()
      if (obj.chunk) handlers.onChunk?.(obj.chunk)
    }
    if (obj.user_message !== undefined) {
      if (!obj.user_message || typeof obj.user_message !== 'object'
          || Array.isArray(obj.user_message)) return fail()
      handlers.onUserMessage?.(obj.user_message)
    }
    return false
  }

  const acceptLine = (line) => {
    if (line === '') return dispatch()
    if (line.startsWith(':')) return false
    const separator = line.indexOf(':')
    const field = separator === -1 ? line : line.slice(0, separator)
    if (field !== 'data') return false
    let value = separator === -1 ? '' : line.slice(separator + 1)
    if (value.startsWith(' ')) value = value.slice(1)
    eventCharacters += value.length + 1
    if (eventCharacters > MAX_STREAM_EVENT_CHARS) return fail()
    dataLines.push(value)
    return false
  }

  const drainLines = (final = false) => {
    while (buffer) {
      let delimiter = -1
      for (let index = scanOffset; index < buffer.length; index += 1) {
        if (buffer[index] === '\n' || buffer[index] === '\r') {
          delimiter = index
          break
        }
      }
      if (delimiter === -1) {
        scanOffset = buffer.length
        break
      }
      if (!final && buffer[delimiter] === '\r' && delimiter === buffer.length - 1) {
        scanOffset = delimiter
        break
      }
      const line = buffer.slice(0, delimiter)
      const delimiterLength = (
        buffer[delimiter] === '\r' && buffer[delimiter + 1] === '\n'
      ) ? 2 : 1
      buffer = buffer.slice(delimiter + delimiterLength)
      scanOffset = 0
      if (acceptLine(line)) return true
    }
    if (final && buffer) {
      const line = buffer
      buffer = ''
      scanOffset = 0
      if (acceptLine(line)) return true
    }
    return false
  }

  try {
    while (!stopped) {
      const { value, done } = await reader.read()
      if (done) break
      streamBytes += value.byteLength
      if (streamBytes > MAX_STREAM_BYTES) {
        fail()
        break
      }
      try {
        buffer += decoder.decode(value, { stream: true })
      } catch {
        fail()
        break
      }
      if (drainLines()) break
    }
    if (!stopped) {
      try {
        buffer += decoder.decode()
      } catch {
        fail()
      }
      if (!stopped) drainLines(true)
    }
    if (!stopped && dataLines.length) dispatch()
    if (!stopped) fail(STREAM_CONNECTION_ERROR)
  } finally {
    try { await reader.cancel() } catch { /* response already closed */ }
  }
}

export const MEDIA_BASE = ''

const PRIVATE_ATTACHMENT_PATH = /^\/api\/attachments\/[1-9]\d*\/download\/$/

export function mediaUrl(url) {
  if (typeof url !== 'string' || !url) return ''
  try {
    const parsed = new URL(url, window.location.origin)
    if (parsed.origin !== window.location.origin
        || parsed.username || parsed.password || parsed.search || parsed.hash
        || !PRIVATE_ATTACHMENT_PATH.test(parsed.pathname)) {
      return ''
    }
    return MEDIA_BASE + parsed.pathname
  } catch {
    return ''
  }
}

export const api = {
  me: () => request('/auth/me/'),
  acceptProviderDisclosure: (version) =>
    request('/provider-disclosure/', {
      method: 'POST', body: JSON.stringify({ version }),
    }),
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
  sendMessageStream: async (
    id, content, model_id, attachment_ids, handlers, signal, idempotencyKey,
  ) => {
    const headers = { 'Content-Type': 'application/json' }
    const csrf = getCookie('csrftoken')
    if (csrf) headers['X-CSRFToken'] = csrf
    if (idempotencyKey) headers['Idempotency-Key'] = idempotencyKey
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
        let body = null
        try { body = await res.json(); detail = body.error || body.detail || detail } catch {}
        handlers.onError?.(detail, res.status, body)
        return
      }
      await consumeEventStream(res, handlers)
    } catch (e) {
      if (e.name === 'AbortError') { handlers.onAbort?.(); return }
      handlers.onError?.(STREAM_CONNECTION_ERROR)
    }
  },
  listAttachments: (kind, cursor = null) => {
    const params = new URLSearchParams({ include_count: '1', limit: '30' })
    if (kind) params.set('kind', kind)
    if (cursor) params.set('cursor', cursor)
    return request(`/attachments/?${params.toString()}`)
  },
  uploadAttachment: (file, modelId, { attemptId, onProgress, signal } = {}) => {
    const fd = new FormData()
    fd.append('file', file)
    if (modelId) fd.append('model_id', modelId)
    if (attemptId) fd.append('upload_attempt_id', attemptId)
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
  cancelAttachmentUpload: (attemptId) =>
    request(`/attachments/upload/${attemptId}/`, { method: 'DELETE', keepalive: true }),
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
  regenerateMessageStream: async (id, handlers, signal, idempotencyKey) => {
    const headers = {}
    const csrf = getCookie('csrftoken')
    if (csrf) headers['X-CSRFToken'] = csrf
    if (idempotencyKey) headers['Idempotency-Key'] = idempotencyKey
    try {
      const res = await fetch(`${BASE}/messages/${id}/regenerate/`, {
        method: 'POST', credentials: 'include', headers, signal,
      })
      if (!res.ok) {
        let detail = `HTTP ${res.status}`
        let body = null
        try { body = await res.json(); detail = body.error || body.detail || detail } catch {}
        handlers.onError?.(detail, res.status, body); return
      }
      await consumeEventStream(res, handlers)
    } catch (e) {
      if (e.name === 'AbortError') { handlers.onAbort?.(); return }
      handlers.onError?.(STREAM_CONNECTION_ERROR)
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
  accountPreferences: () => request('/account/preferences/'),
  updateAccountPreferences: (patch) =>
    request('/account/preferences/', {
      method: 'PATCH', body: JSON.stringify(patch),
    }),
  accountExportUrl: () => `${BASE}/account/export/`,
  accountDeletion: () => request('/account/deletion/'),
  scheduleAccountDeletion: (password, code) =>
    request('/account/deletion/', {
      method: 'POST', body: JSON.stringify({ password, ...(code ? { code } : {}) }),
    }),
  cancelAccountDeletion: (password, code) =>
    request('/account/deletion/', {
      method: 'DELETE', body: JSON.stringify({ password, ...(code ? { code } : {}) }),
    }),
  chatRetention: () => request('/account/chat-retention/'),
  updateChatRetention: (archived_days) =>
    request('/account/chat-retention/', {
      method: 'PATCH', body: JSON.stringify({ archived_days }),
    }),
  reauthenticate: (password, code) =>
    request('/auth/reauthenticate/', {
      method: 'POST', body: JSON.stringify({ password, ...(code ? { code } : {}) }),
    }),
  reauthenticateAdmin: (password, code) =>
    request('/auth/admin-reauthenticate/', {
      method: 'POST', body: JSON.stringify({ password, code }),
    }),
  changePassword: (current_password, new_password, code) =>
    request('/auth/password/', {
      method: 'POST',
      body: JSON.stringify({ current_password, new_password, ...(code ? { code } : {}) }),
    }),
  deleteAccount: (password, code) =>
    request('/auth/delete-account/', { method: 'POST', body: JSON.stringify({ password, ...(code ? { code } : {}) }) }),

  // Sessions
  listSessions: () => request('/auth/sessions/'),
  revokeSession: (key) => request(`/auth/sessions/${encodeURIComponent(key)}/`, { method: 'DELETE' }),
  revokeOtherSessions: () => request('/auth/sessions/revoke-others/', { method: 'DELETE' }),
}
