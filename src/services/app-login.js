// "Sign in with Snapie" for registered third-party apps (web + native).
// Clients come from APP_LOGIN_CLIENTS (JSON), e.g.
//   {"iot":{"name":"Hive IoT","redirects":["https://iot.menosoft.xyz/auth/callback","menoiot://auth"]}}
// The client id doubles as the token audience.

const CLIENT_ID = /^[a-z0-9_-]{1,32}$/i
const STATE = /^[A-Za-z0-9_-]{16,128}$/
const FORBIDDEN_SCHEMES = ['http:', 'javascript:', 'data:', 'file:', 'blob:', 'about:', 'vbscript:']

function parseRedirect(value) {
  let url
  try { url = new URL(value) } catch { return null }
  if (url.username || url.password || url.hash) return null
  if (FORBIDDEN_SCHEMES.includes(url.protocol)) return null
  return url
}

export function loadClients(raw = process.env.APP_LOGIN_CLIENTS) {
  if (!raw) return {}
  let parsed
  try { parsed = JSON.parse(raw) } catch { return {} }
  const clients = {}
  for (const [id, c] of Object.entries(parsed || {})) {
    if (!CLIENT_ID.test(id)) continue
    const redirects = (Array.isArray(c?.redirects) ? c.redirects : []).filter(r => typeof r === 'string' && parseRedirect(r))
    if (!redirects.length) continue
    clients[id] = { id, name: String(c.name || id).slice(0, 64), redirects }
  }
  return clients
}

export function getClient(id, clients = loadClients()) {
  return typeof id === 'string' && Object.hasOwn(clients, id) ? clients[id] : null
}

// Exact match on scheme + host + path. The query is the caller's; fragments are rejected.
export function isAllowedRedirect(client, redirect) {
  const url = typeof redirect === 'string' ? parseRedirect(redirect) : null
  if (!url || !client) return false
  return client.redirects.some((allowed) => {
    const a = new URL(allowed)
    return a.protocol === url.protocol && a.host === url.host && a.pathname === url.pathname
  })
}

export const isValidState = (state) => typeof state === 'string' && STATE.test(state)
