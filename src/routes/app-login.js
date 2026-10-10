import { Router } from 'express'
import { asyncMw } from '../services/async-middleware.js'
import { authMiddleware } from '../services/auth.js'
import { csrfMiddleware } from '../services/csrf.js'
import { getUserById } from '../services/users.js'
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

export default router
