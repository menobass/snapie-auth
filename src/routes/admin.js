import { Router } from 'express'
import { asyncMw } from '../services/async-middleware.js'
import { authMiddleware, toOid } from '../services/auth.js'
import { csrfMiddleware } from '../services/csrf.js'
import { getAccount, broadcastOps, hiveErr } from '../services/hive.js'
import { users, accountJobs } from '../services/db.js'
import { issueToken, listTokens, revokeToken } from '../services/sponsor-tokens.js'
import { sendSponsorInviteEmail } from '../services/email.js'
import { hashEmail } from '../services/users.js'

const router = Router()

function requireAdmin(req, res, next) {
  if (!req.user?.isAdmin) return res.status(403).json({ error: 'admin_required' })
  next()
}

// GET /api/admin/stats
router.get('/stats', authMiddleware, requireAdmin, asyncMw(async (req, res) => {
  const [snapieAccount, pendingJobs, userCount] = await Promise.all([
    getAccount(process.env.SNAPIE_ACCOUNT),
    accountJobs().countDocuments({ status: 'pending' }),
    users().countDocuments()
  ])

  res.json({
    actCount: snapieAccount?.pending_claimed_accounts || 0,
    pendingJobs,
    userCount
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
