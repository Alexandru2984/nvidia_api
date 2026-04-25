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
    const err = new Error('Unauthorized')
    err.status = res.status
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
  login: (username, password) =>
    request('/auth/login/', { method: 'POST', body: JSON.stringify({ username, password }) }),
  logout: () => request('/auth/logout/', { method: 'POST' }),
  register: (username, email, password) =>
    request('/auth/register/', { method: 'POST', body: JSON.stringify({ username, email, password }) }),
  verifyCode: (email, code) =>
    request('/auth/verify/', { method: 'POST', body: JSON.stringify({ email, code }) }),
  resend: (email) =>
    request('/auth/resend/', { method: 'POST', body: JSON.stringify({ email }) }),
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
  sendMessage: (id, content, model_id, attachment_ids) =>
    request(`/conversations/${id}/messages/`, {
      method: 'POST',
      body: JSON.stringify({
        content,
        ...(model_id ? { model_id } : {}),
        ...(attachment_ids && attachment_ids.length ? { attachment_ids } : {}),
      }),
    }),
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
}
