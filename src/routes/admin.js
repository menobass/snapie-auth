import { Router } from 'express'
import { asyncMw } from '../services/async-middleware.js'
import { authMiddleware, toOid } from '../services/auth.js'
import { csrfMiddleware } from '../services/csrf.js'
import { getAccount, broadcastOps, hiveErr } from '../services/hive.js'
import { users, accountJobs, paymentIntents } from '../services/db.js'
import { issueToken, listTokens, revokeToken } from '../services/sponsor-tokens.js'
import { sendSponsorInviteEmail } from '../services/email.js'
import { hashEmail } from '../services/users.js'

const router = Router()

function requireAdmin(req, res, next) {
  if (!req.user?.isAdmin) return res.status(403).json({ error: 'admin_required' })
  next()
}

// Custodial accounts younger than the emancipation hold — the abuse-review queue.
function heldAccountsFilter() {
  const minDays = parseFloat(process.env.EMANCIPATION_MIN_AGE_DAYS || '30')
  const cutoff = new Date(Date.now() - minDays * 86400000)
  return { custodyMode: 'custodial', createdAt: { $gte: cutoff } }
}

function escapeRegex(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

function shapeAdminUser(u) {
  return {
    userId: u._id.toString(),
    hiveUsername: u.hiveUsername || null,
    name: u.name || null,
    provider: u.provider,
    custodyMode: u.custodyMode || null,
    createdAt: u.createdAt,
    disabled: u.disabled || false,
    disabledReason: u.disabledReason || null,
    disabledAt: u.disabledAt || null
  }
}

// GET /api/admin/stats
router.get('/stats', authMiddleware, requireAdmin, asyncMw(async (req, res) => {
  const [snapieAccount, pendingJobs, userCount, incompleteOnboarding, heldAccounts] = await Promise.all([
    getAccount(process.env.SNAPIE_ACCOUNT),
    accountJobs().countDocuments({ status: 'pending' }),
    users().countDocuments(),
    users().countDocuments({ hiveUsername: null, emailVerified: true }),
    users().countDocuments(heldAccountsFilter())
  ])

  res.json({
    actCount: snapieAccount?.pending_claimed_accounts || 0,
    pendingJobs,
    userCount,
    incompleteOnboarding,
    heldAccounts
  })
}))

// GET /api/admin/incomplete-onboarding
router.get('/incomplete-onboarding', authMiddleware, requireAdmin, asyncMw(async (req, res) => {
  const list = await users()
    .find({ hiveUsername: null, emailVerified: true })
    .sort({ createdAt: 1 })
    .limit(200)
    .project({ _id: 1, provider: 1, name: 1, createdAt: 1 })
    .toArray()

  res.json({
    count: list.length,
    users: list.map(u => ({
      userId: u._id.toString(),
      provider: u.provider,
      name: u.name || null,
      createdAt: u.createdAt
    }))
  })
}))

// GET /api/admin/jobs
router.get('/jobs', authMiddleware, requireAdmin, asyncMw(async (req, res) => {
  const jobs = await accountJobs()
    .find({})
    .sort({ createdAt: -1 })
    .limit(100)
    .toArray()

  res.json({ jobs: jobs.map(j => ({
    jobId: j._id,
    userId: j.userId,
    username: j.username,
    status: j.status,
    txId: j.txId || null,
    error: j.lastError || null,
    attempts: j.attempts,
    sponsorTokenId: j.sponsorTokenId || null,
    provisionNote: j.provisionNote || null,
    createdAt: j.createdAt,
    confirmedAt: j.confirmedAt || null
  })) })
}))

// POST /api/admin/claim-act
router.post('/claim-act', authMiddleware, requireAdmin, csrfMiddleware, asyncMw(async (req, res) => {
  const op = ['claim_account', {
    creator: process.env.SNAPIE_ACCOUNT,
    fee: '0.000 HIVE',
    extensions: []
  }]
  try {
    const result = await broadcastOps([op], process.env.SNAPIE_ACTIVE_KEY)
    res.json({ ok: true, txId: result.id })
  } catch (err) {
    res.status(500).json({ error: hiveErr(err) })
  }
}))

// GET /api/admin/payment-intents
// Query params: status (pending|confirmed|expired), limit (default 50, max 200)
router.get('/payment-intents', authMiddleware, requireAdmin, asyncMw(async (req, res) => {
  const { status, limit = '50' } = req.query
  const filter = status ? { status } : {}
  const intents = await paymentIntents()
    .find(filter)
    .sort({ createdAt: -1 })
    .limit(Math.min(parseInt(limit) || 50, 200))
    .toArray()

  res.json({
    intents: intents.map(i => ({
      memo: i._id,
      userId: i.userId,
      type: i.type,
      status: i.status,
      amountHive: i.amountHive,
      amountUsd: i.amountUsd,
      txId: i.txId || null,
      createdAt: i.createdAt,
      confirmedAt: i.confirmedAt || null,
      expiresAt: i.expiresAt
    }))
  })
}))

// ── Sponsor token management ──────────────────────────────────

// GET /api/admin/sponsor-tokens
router.get('/sponsor-tokens', authMiddleware, requireAdmin, asyncMw(async (req, res) => {
  const includeUsed = req.query.includeUsed !== 'false'
  const tokens = await listTokens({ includeUsed })
  res.json({ tokens })
}))

// POST /api/admin/sponsor-tokens
// Body: { email, note?, expiresInDays?, sendEmail? }
router.post('/sponsor-tokens', authMiddleware, requireAdmin, csrfMiddleware, asyncMw(async (req, res) => {
  const { email, note = null, expiresInDays = null, sendEmail = false } = req.body

  if (!email || typeof email !== 'string' || !email.includes('@')) {
    return res.status(400).json({ error: 'valid email required' })
  }

  const token = await issueToken({
    email,
    note,
    issuedBy: 'admin',
    issuedByUserId: req.user.userId,
    expiresInDays: expiresInDays ? Number(expiresInDays) : null
  })

  let emailSent = false
  let emailError = null

  if (sendEmail) {
    try {
      await sendSponsorInviteEmail(email, note)
      emailSent = true
    } catch (err) {
      console.error('Sponsor invite email failed:', err)
      emailError = 'Email delivery failed — invite was created successfully.'
    }
  }

  res.status(201).json({
    tokenId: token._id,
    email,
    note: token.note,
    expiresAt: token.expiresAt,
    createdAt: token.createdAt,
    emailSent,
    emailError
  })
}))

// DELETE /api/admin/sponsor-tokens/:tokenId
router.delete('/sponsor-tokens/:tokenId', authMiddleware, requireAdmin, csrfMiddleware, asyncMw(async (req, res) => {
  const deleted = await revokeToken(req.params.tokenId)
  if (!deleted) {
    return res.status(404).json({ error: 'token not found or already used' })
  }
  res.json({ ok: true })
}))

// ── Account search / disable (abuse review) ─────────────────────

// GET /api/admin/users?q=<term> — search by hiveUsername (prefix) or name
router.get('/users', authMiddleware, requireAdmin, asyncMw(async (req, res) => {
  const q = (req.query.q || '').toString().trim()
  if (!q) return res.json({ users: [] })

  const pattern = new RegExp('^' + escapeRegex(q), 'i')
  const list = await users()
    .find({ $or: [{ hiveUsername: pattern }, { name: pattern }] })
    .limit(25)
    .toArray()

  res.json({ users: list.map(shapeAdminUser) })
}))

// GET /api/admin/held-accounts — custodial accounts still inside the emancipation hold window
router.get('/held-accounts', authMiddleware, requireAdmin, asyncMw(async (req, res) => {
  const minDays = parseFloat(process.env.EMANCIPATION_MIN_AGE_DAYS || '30')
  const list = await users()
    .find(heldAccountsFilter())
    .sort({ createdAt: -1 })
    .limit(200)
    .toArray()

  res.json({
    minAgeDays: minDays,
    users: list.map(u => ({
      ...shapeAdminUser(u),
      eligibleAt: new Date(new Date(u.createdAt).getTime() + minDays * 86400000)
    }))
  })
}))

// POST /api/admin/users/:userId/disable — body: { reason }
router.post('/users/:userId/disable', authMiddleware, requireAdmin, csrfMiddleware, asyncMw(async (req, res) => {
  const oid = toOid(req.params.userId)
  if (!oid) return res.status(400).json({ error: 'invalid_user_id' })

  const { reason } = req.body
  if (!reason || typeof reason !== 'string' || !reason.trim() || reason.length > 500) {
    return res.status(400).json({ error: 'reason required (1-500 chars)' })
  }

  const result = await users().findOneAndUpdate(
    { _id: oid },
    {
      $set: {
        disabled: true,
        disabledReason: reason.trim(),
        disabledAt: new Date(),
        disabledBy: req.user.userId
      }
    },
    { returnDocument: 'after' }
  )
  if (!result) return res.status(404).json({ error: 'user_not_found' })

  res.json(shapeAdminUser(result))
}))

// POST /api/admin/users/:userId/enable
router.post('/users/:userId/enable', authMiddleware, requireAdmin, csrfMiddleware, asyncMw(async (req, res) => {
  const oid = toOid(req.params.userId)
  if (!oid) return res.status(400).json({ error: 'invalid_user_id' })

  const result = await users().findOneAndUpdate(
    { _id: oid },
    { $set: { disabled: false, disabledReason: null, disabledAt: null, disabledBy: null } },
    { returnDocument: 'after' }
  )
  if (!result) return res.status(404).json({ error: 'user_not_found' })

  res.json(shapeAdminUser(result))
}))

// ── Admin user management ──────────────────────────────────────

// GET /api/admin/admins
router.get('/admins', authMiddleware, requireAdmin, asyncMw(async (req, res) => {
  const admins = await users().find({ isAdmin: true }).toArray()
  res.json({
    admins: admins.map(u => ({
      userId: u._id.toString(),
      name: u.name || null,
      provider: u.provider,
      createdAt: u.createdAt
    }))
  })
}))

// POST /api/admin/admins — grant admin by email (user must already be registered)
router.post('/admins', authMiddleware, requireAdmin, csrfMiddleware, asyncMw(async (req, res) => {
  const { email } = req.body
  if (!email || typeof email !== 'string' || !email.includes('@')) {
    return res.status(400).json({ error: 'valid email required' })
  }

  const emailHash = hashEmail(email)
  const user = await users().findOneAndUpdate(
    { emailHash },
    { $set: { isAdmin: true } },
    { returnDocument: 'after' }
  )

  if (!user) {
    return res.status(404).json({ error: 'user_not_found' })
  }

  res.json({
    userId: user._id.toString(),
    name: user.name || null,
    provider: user.provider
  })
}))

// DELETE /api/admin/admins/:userId — revoke admin
router.delete('/admins/:userId', authMiddleware, requireAdmin, csrfMiddleware, asyncMw(async (req, res) => {
  if (req.params.userId === req.user.userId) {
    return res.status(400).json({ error: 'cannot_demote_self' })
  }

  const oid = toOid(req.params.userId)
  if (!oid) return res.status(400).json({ error: 'invalid_user_id' })

  const result = await users().updateOne({ _id: oid }, { $set: { isAdmin: false } })
  if (result.matchedCount === 0) {
    return res.status(404).json({ error: 'user_not_found' })
  }

  res.json({ ok: true })
}))

export default router
