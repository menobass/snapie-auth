import crypto from 'crypto'
import jwt from 'jsonwebtoken'
import { Router } from 'express'
import argon2 from 'argon2'
import { asyncMw } from '../services/async-middleware.js'
import { authMiddleware, clearSessionCookie } from '../services/auth.js'
import { csrfMiddleware, clearCsrfCookie, setCsrfCookie, CSRF_COOKIE } from '../services/csrf.js'
import { upsertUser, startSession, shapeUser, getUserById, hashEmail } from '../services/users.js'
import { getAccountValue, isEmancipationRequired } from '../services/account-value.js'
import { users, emailVerifications } from '../services/db.js'
import { sendVerificationEmail } from '../services/email.js'

const BASE_URL = () => process.env.AUTH_BASE_URL || 'https://auth.snapie.io'

async function createVerificationToken(emailHash) {
  const token = crypto.randomBytes(32).toString('hex')
  const now = new Date()
  await emailVerifications().insertOne({
    token,
    emailHash,
    createdAt: now,
    expiresAt: new Date(now.getTime() + 24 * 60 * 60 * 1000)
  })
  return token
}

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
    picture: googleUser.picture || null,
    emailVerified: true
  })

  const shaped = startSession(res, user, googleUser.email)
  res.json({ user: shaped })
}))

// Apple JWKS — cached for 1 hour to avoid hitting Apple on every login
let appleKeysCache = null
let appleKeysCachedAt = 0

async function getApplePublicKeys() {
  const now = Date.now()
  if (appleKeysCache && now - appleKeysCachedAt < 60 * 60 * 1000) return appleKeysCache
  const res = await fetch('https://appleid.apple.com/auth/keys', { signal: AbortSignal.timeout(5000) })
  if (!res.ok) throw new Error('failed to fetch Apple public keys')
  const { keys } = await res.json()
  appleKeysCache = keys
  appleKeysCachedAt = now
  return keys
}

async function verifyAppleToken(identityToken) {
  const [headerB64] = identityToken.split('.')
  let header
  try { header = JSON.parse(Buffer.from(headerB64, 'base64url').toString()) } catch { return null }

  const keys = await getApplePublicKeys()
  const jwk = keys.find(k => k.kid === header.kid)
  if (!jwk) return null

  const publicKey = crypto.createPublicKey({ key: jwk, format: 'jwk' })
  try {
    const payload = jwt.verify(identityToken, publicKey, {
      algorithms: ['RS256'],
      issuer: 'https://appleid.apple.com',
      audience: process.env.APPLE_CLIENT_ID  // App Bundle ID, e.g. "io.snapie.app"
    })
    if (!payload.sub) return null
    return payload
  } catch { return null }
}

// POST /api/auth/apple
router.post('/apple', asyncMw(async (req, res) => {
  const { identityToken, name } = req.body
  if (!identityToken || typeof identityToken !== 'string') {
    return res.status(400).json({ error: 'identityToken required' })
  }

  const appleUser = await verifyAppleToken(identityToken)
  if (!appleUser) {
    return res.status(401).json({ error: 'invalid_credential' })
  }

  // Apple only sends email and name on the very first sign-in.
  // On subsequent logins both will be absent — upsertUser preserves whatever was saved.
  const email = typeof appleUser.email === 'string' ? appleUser.email : null
  const emailHash = email ? hashEmail(email) : null

  let displayName = null
  if (name && typeof name === 'object') {
    const parts = [name.firstName, name.lastName].filter(Boolean)
    if (parts.length) displayName = parts.join(' ')
  }

  const user = await upsertUser({
    provider: 'apple',
    providerId: appleUser.sub,
    emailHash,
    name: displayName,
    picture: null,
    emailVerified: true
  })

  const shaped = startSession(res, user, email)
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

  const existing = await users().findOne({ provider: 'email', providerId })
  if (existing) {
    if (!existing.emailVerified) {
      // Resend verification rather than revealing the account exists
      const token = await createVerificationToken(emailHash)
      await sendVerificationEmail(email, token)
      return res.status(202).json({ pending: true })
    }
    if (!existing.hiveUsername) {
      return res.status(409).json({ error: 'login_to_claim_hive' })
    }
    return res.status(409).json({ error: 'email_already_registered' })
  }

  const passwordHash = await argon2.hash(password, { type: argon2.argon2id })

  const user = await upsertUser({
    provider: 'email',
    providerId,
    emailHash,
    name: null,
    picture: null,
    emailVerified: false
  })

  await users().updateOne({ _id: user._id }, { $set: { passwordHash } })

  const token = await createVerificationToken(emailHash)
  await sendVerificationEmail(email, token)

  res.status(202).json({ pending: true })
}))

// GET /api/auth/email/verify?token=xxx  (link from email)
router.get('/email/verify', asyncMw(async (req, res) => {
  const { token } = req.query
  if (!token) return res.redirect(`/?error=invalid_token`)

  const record = await emailVerifications().findOneAndDelete({ token })
  if (!record) return res.redirect(`/?error=invalid_token`)

  const user = await users().findOneAndUpdate(
    { provider: 'email', emailHash: record.emailHash },
    { $set: { emailVerified: true, updatedAt: new Date() } },
    { returnDocument: 'after' }
  )
  if (!user) return res.redirect(`/?error=invalid_token`)

  // Recover the plaintext email from the JWT-less context isn't possible here,
  // so we start a session without the email claim — it's cosmetic only.
  startSession(res, user, null)
  res.redirect('/manage.html')
}))

// POST /api/auth/email/resend — resend verification email
router.post('/email/resend', asyncMw(async (req, res) => {
  const { email } = req.body
  if (!email || typeof email !== 'string') {
    return res.status(400).json({ error: 'email required' })
  }

  const emailHash = hashEmail(email)
  const user = await users().findOne({ provider: 'email', emailHash })

  // Always return 200 to avoid email enumeration
  if (!user || user.emailVerified) {
    return res.json({ ok: true })
  }

  // Delete any existing pending tokens for this email before issuing a new one
  await emailVerifications().deleteMany({ emailHash })
  const token = await createVerificationToken(emailHash)
  await sendVerificationEmail(email, token)

  res.json({ ok: true })
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

  if (!user.emailVerified) {
    return res.status(403).json({ error: 'email_not_verified' })
  }

  const shaped = startSession(res, user, email)
  res.json({ user: shaped })
}))

// GET /api/auth/me
router.get('/me', authMiddleware, asyncMw(async (req, res) => {
  const user = await getUserById(req.user.userId)
  if (!user) return res.status(401).json({ error: 'Unauthorized' })

  // Bootstrap: auto-grant admin if email matches ADMIN_EMAILS env var
  const adminEmails = (process.env.ADMIN_EMAILS || '')
    .split(',').map(e => e.trim().toLowerCase()).filter(Boolean)
  const userEmail = req.user.email || null
  if (adminEmails.length && userEmail && adminEmails.includes(userEmail.toLowerCase()) && !user.isAdmin) {
    await users().updateOne({ _id: user._id }, { $set: { isAdmin: true } })
    user.isAdmin = true
  }

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
