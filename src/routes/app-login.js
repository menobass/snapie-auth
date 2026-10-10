import { Router } from 'express'
import { asyncMw } from '../services/async-middleware.js'
import { authMiddleware } from '../services/auth.js'
import { csrfMiddleware } from '../services/csrf.js'
import crypto from 'crypto'
import { getUserById, upsertUser, hashEmail } from '../services/users.js'
import { verifyAppleIdentityToken } from '../services/apple.js'
import { getClient, isAllowedRedirect, isValidState } from '../services/app-login.js'
import { isConfigured, mintAppToken } from '../services/app-tokens.js'

const router = Router()

// GET /api/app-login/client?id=iot&redirect=...
// Lets login.html show the app name and refuse untrusted redirects before the user signs in.
router.get('/client', (req, res) => {
  const client = getClient(req.query.id)
  if (!client) return res.status(404).json({ error: 'invalid_client' })
  if (!isAllowedRedirect(client, req.query.redirect)) return res.status(400).json({ error: 'invalid_redirect' })
  res.json({ id: client.id, name: client.name })
})

// POST /api/app-login/token  { client, redirect, state }   (session + CSRF)
// Returns a short-lived RS256 JWT (aud = client, sub = Snapie user id, nonce = state) that the
// app's backend verifies against /.well-known/jwks.json.
router.post('/token', authMiddleware, csrfMiddleware, asyncMw(async (req, res) => {
  if (!isConfigured()) return res.status(503).json({ status: 'error', error: 'app_login_not_configured' })
  const { client: clientId, redirect, state } = req.body || {}
  const client = getClient(clientId)
  if (!client) return res.status(400).json({ status: 'error', error: 'invalid_client' })
  if (!isAllowedRedirect(client, redirect)) return res.status(400).json({ status: 'error', error: 'invalid_redirect' })
  if (!isValidState(state)) return res.status(400).json({ status: 'error', error: 'invalid_state' })

  const user = await getUserById(req.user.userId)
  if (!user) return res.status(401).json({ error: 'Unauthorized' })
  if (user.disabled) return res.status(403).json({ status: 'error', error: 'account_disabled' })

  res.json({ status: 'ok', token: mintAppToken({ client, user, state }) })
}))

// POST /api/app-login/apple  { client, identityToken, state, name? }
// Native iOS "Sign in with Apple" -> the same app token as /token, so the app's backend verifies
// one kind of token. No cookie or session is created. The client must list its bundle ID under
// `apple` in APP_LOGIN_CLIENTS. The Apple token must carry nonce = sha256_hex(state), which ties the
// Apple credential to this one login attempt (a captured identity token can't be replayed).
router.post('/apple', asyncMw(async (req, res) => {
  if (!isConfigured()) return res.status(503).json({ status: 'error', error: 'app_login_not_configured' })
  const { client: clientId, identityToken, state, name } = req.body || {}
  const client = getClient(clientId)
  if (!client) return res.status(400).json({ status: 'error', error: 'invalid_client' })
  if (!client.apple.length) return res.status(400).json({ status: 'error', error: 'apple_not_enabled' })
  if (!isValidState(state)) return res.status(400).json({ status: 'error', error: 'invalid_state' })
  if (typeof identityToken !== 'string' || identityToken.length > 4096)
    return res.status(400).json({ status: 'error', error: 'identityToken required' })

  const apple = await verifyAppleIdentityToken(identityToken, client.apple)
  const expectedNonce = crypto.createHash('sha256').update(state).digest('hex')
  if (!apple || apple.nonce !== expectedNonce) return res.status(401).json({ status: 'error', error: 'invalid_credential' })

  // Apple sends the name only on the very first authorization, and only the app sees it.
  const parts = name && typeof name === 'object' ? [name.firstName, name.lastName].filter(v => typeof v === 'string' && v) : []
  const email = typeof apple.email === 'string' ? apple.email : null
  const user = await upsertUser({
    provider: 'apple',
    providerId: apple.sub,
    emailHash: email ? hashEmail(email) : null,
    name: parts.length ? parts.join(' ').slice(0, 64) : null,
    picture: null,
    emailVerified: true
  })
  if (user.disabled) return res.status(403).json({ status: 'error', error: 'account_disabled' })

  res.json({ status: 'ok', token: mintAppToken({ client, user, state }) })
}))

export default router
