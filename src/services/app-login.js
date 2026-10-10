// "Sign in with Snapie" for registered third-party apps (web + native).
// Clients come from APP_LOGIN_CLIENTS (JSON), e.g.
//   {"iot":{"name":"Flex IOT","redirects":["https://iot.example.com/auth/callback","myapp://auth"],
//           "apple":["com.example.myapp"], "google":["1234-abc.apps.googleusercontent.com"]}}
// The client id doubles as the token audience. `apple` lists the iOS bundle IDs (or Services IDs)
// allowed as the audience of a native Sign in with Apple identity token for this client; `google`
// lists the Google OAuth client IDs allowed as the audience of a native Google ID token.

const CLIENT_ID = /^[a-z0-9_-]{1,32}$/i
const STATE = /^[A-Za-z0-9_-]{16,128}$/
const APPLE_AUDIENCE = /^[A-Za-z0-9.-]{1,155}$/
const GOOGLE_AUDIENCE = /^[A-Za-z0-9._-]{1,200}$/
const list = (v) => (Array.isArray(v) ? v : v ? [v] : [])
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
    const apple = list(c.apple).filter(a => typeof a === 'string' && APPLE_AUDIENCE.test(a))
    const google = list(c.google).filter(a => typeof a === 'string' && GOOGLE_AUDIENCE.test(a))
    clients[id] = { id, name: String(c.name || id).slice(0, 64), redirects, apple, google }
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
