const BASE = import.meta.env.DEV ? 'http://127.0.0.1:8500/api' : '/api'

function getCookie(name) {
  const m = document.cookie.match(new RegExp('(?:^|; )' + name + '=([^;]*)'))
  return m ? decodeURIComponent(m[1]) : null
}

async function request(path, opts = {}) {
  const method = (opts.method || 'GET').toUpperCase()
  const headers = { 'Content-Type': 'application/json', ...(opts.headers || {}) }
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
  sendMessage: (id, content, model_id) =>
    request(`/conversations/${id}/messages/`, {
      method: 'POST',
      body: JSON.stringify({ content, ...(model_id ? { model_id } : {}) }),
    }),
}
