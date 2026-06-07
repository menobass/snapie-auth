// Shared utilities for snapie-auth frontend

export function getCsrfToken() {
  const match = document.cookie.match(/(?:^|;\s*)snapieauth_csrf=([^;]+)/)
  return match ? decodeURIComponent(match[1]) : null
}

export async function api(method, path, body) {
  const opts = {
    method,
    credentials: 'include',
    headers: {}
  }
  if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json'
    opts.body = JSON.stringify(body)
  }
  const csrf = getCsrfToken()
  if (csrf && method !== 'GET') {
    opts.headers['x-csrf-token'] = csrf
  }
  const res = await fetch(`/api${path}`, opts)
  const data = await res.json().catch(() => ({}))
  if (!res.ok) throw Object.assign(new Error(data.error || res.statusText), { status: res.status, data })
  return data
}

export async function checkAuth() {
  try {
    return await api('GET', '/auth/me')
  } catch {
    return null
  }
}

export async function getPublicConfig() {
  const res = await fetch('/api/public-config')
  return res.ok ? res.json() : {}
}

export function copyToClipboard(text, btn) {
  navigator.clipboard.writeText(text).then(() => {
    btn.textContent = 'Copied!'
    btn.classList.add('copied')
    setTimeout(() => {
      btn.textContent = 'Copy'
      btn.classList.remove('copied')
    }, 2000)
  })
}

export function showAlert(container, message, type = 'info') {
  const existing = container.querySelector('.alert')
  if (existing) existing.remove()
  const div = document.createElement('div')
  div.className = `alert alert-${type}`
  div.textContent = message
  container.prepend(div)
}

export function setLoading(btn, loading) {
  if (loading) {
    btn.dataset.originalText = btn.innerHTML
    btn.innerHTML = '<span class="spinner"></span>'
    btn.disabled = true
  } else {
    btn.innerHTML = btn.dataset.originalText || btn.textContent
    btn.disabled = false
  }
}
