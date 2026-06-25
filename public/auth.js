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

// Shared by login.html and login-callback.html — navigates the browser to
// the plugin's redirect URL with the activation result appended.
export function redirectWithLicenseResult({ redirect, plugin, machine }, result) {
  const url = new URL(redirect)
  url.searchParams.set('plugin', plugin)
  url.searchParams.set('machine', machine)
  url.searchParams.set('status', result.status || 'error')
  if (result.hiveUser) url.searchParams.set('hive_user', result.hiveUser)
  if (result.error) url.searchParams.set('error', result.error)

  sessionStorage.removeItem('snapie_license_pending')
  window.location.href = url.toString()
}

// Calls the license activation endpoint (requires an active session) and
// redirects with the result. Used once sign-in has succeeded.
export async function completeLicenseActivation(pending) {
  let result
  try {
    result = await api('POST', '/license/activate', { plugin: pending.plugin, machine: pending.machine })
  } catch (err) {
    result = { status: 'error', error: err.data?.error || 'request_failed' }
  }
  redirectWithLicenseResult(pending, result)
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
