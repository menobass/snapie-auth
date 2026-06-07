import { Router } from 'express'
import argon2 from 'argon2'
import { asyncMw } from '../services/async-middleware.js'
import { authMiddleware, clearSessionCookie } from '../services/auth.js'
import { csrfMiddleware, clearCsrfCookie, setCsrfCookie, CSRF_COOKIE } from '../services/csrf.js'
import { upsertUser, startSession, shapeUser, getUserById, hashEmail } from '../services/users.js'
import { getAccountValue, isEmancipationRequired } from '../services/account-value.js'
import { users } from '../services/db.js'

const router = Router()

async function verifyGoogleToken(credential) {
  const res = await fetch(
    `https://oauth2.googleapis.com/tokeninfo?id_token=${encodeURIComponent(credential)}`,
    { signal: AbortSignal.timeout(5000) }
  )
  if (!res.ok) return null
  const data = await res.json()

  const clientId = process.env.GOOGLE_CLIENT_ID
  if (clientId && data.aud !== clientId) return null
  if (!data.sub) return null

  return data
}

// POST /api/auth/google
router.post('/google', asyncMw(async (req, res) => {
  const { credential } = req.body
  if (!credential || typeof credential !== 'string') {
    return res.status(400).json({ error: 'credential required' })
  }

  const googleUser = await verifyGoogleToken(credential)
  if (!googleUser) {
    return res.status(401).json({ error: 'invalid_credential' })
  }

  const emailHash = googleUser.email ? hashEmail(googleUser.email) : null
  const user = await upsertUser({
    provider: 'google',
    providerId: googleUser.sub,
    emailHash,
    name: googleUser.name || null,
    picture: googleUser.picture || null
  })

  const shaped = startSession(res, user, googleUser.email)
  res.json({ user: shaped })
}))

// POST /api/auth/email/register
router.post('/email/register', asyncMw(async (req, res) => {
  const { email, password } = req.body
  if (!email || !password) {
    return res.status(400).json({ error: 'email and password required' })
  }
  if (typeof email !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'invalid input' })
  }
  if (password.length < 8) {
    return res.status(400).json({ error: 'password_too_short' })
  }

  const emailHash = hashEmail(email)
  const providerId = emailHash

  // Check if already registered
  const existing = await users().findOne({ provider: 'email', providerId })
  if (existing) {
    return res.status(409).json({ error: 'email_already_registered' })
  }

  const passwordHash = await argon2.hash(password, { type: argon2.argon2id })

  const user = await upsertUser({
    provider: 'email',
    providerId,
    emailHash,
    name: null,
    picture: null
  })

  // Store passwordHash
  await users().updateOne(
    { _id: user._id },
    { $set: { passwordHash } }
  )

  const shaped = startSession(res, user, email)
  res.status(201).json({ user: shaped })
}))

// POST /api/auth/email/login
router.post('/email/login', asyncMw(async (req, res) => {
  const { email, password } = req.body
  if (!email || !password) {
    return res.status(400).json({ error: 'email and password required' })
  }

  const emailHash = hashEmail(email)
  const user = await users().findOne({ provider: 'email', providerId: emailHash })
  if (!user || !user.passwordHash) {
    return res.status(401).json({ error: 'invalid_credentials' })
  }

  const valid = await argon2.verify(user.passwordHash, password)
  if (!valid) {
    return res.status(401).json({ error: 'invalid_credentials' })
  }

  const shaped = startSession(res, user, email)
  res.json({ user: shaped })
}))

// GET /api/auth/me
router.get('/me', authMiddleware, asyncMw(async (req, res) => {
  const user = await getUserById(req.user.userId)
  if (!user) return res.status(401).json({ error: 'Unauthorized' })

  // Refresh CSRF if missing
  if (!req.cookies?.[CSRF_COOKIE]) {
    setCsrfCookie(res)
  }

  let accountValueUsd = null
  let emancipationRequired = false

  if (user.hiveUsername && user.custodyMode === 'custodial') {
    try {
      const value = await getAccountValue(user.hiveUsername)
      if (value) {
        accountValueUsd = value.totalValueUsd
        emancipationRequired = isEmancipationRequired('custodial', accountValueUsd)
      }
    } catch {
      // non-fatal
    }
  }

  res.json({
    user: {
      ...shapeUser(user, { accountValueUsd, emancipationRequired }),
      email: req.user.email || null
    }
  })
}))

// POST /api/auth/logout
router.post('/logout', asyncMw(async (req, res) => {
  clearSessionCookie(res)
  clearCsrfCookie(res)
  res.json({ ok: true })
}))

export default router
