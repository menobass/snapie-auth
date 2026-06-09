import { Router } from 'express'
import crypto from 'crypto'
import { asyncMw } from '../services/async-middleware.js'
import { authMiddleware } from '../services/auth.js'
import { csrfMiddleware } from '../services/csrf.js'
import { verifyHiveIdentity, hasPostingAuthority } from '../services/hive.js'
import { users, linkNonces } from '../services/db.js'
import { getUserById } from '../services/users.js'

const router = Router()

// POST /api/link/verify-challenge
// Issues a nonce for the user to sign with their Hive posting key
router.post('/verify-challenge', authMiddleware, asyncMw(async (req, res) => {
  const challenge = `snapie-auth:link:${Date.now()}:${crypto.randomBytes(16).toString('hex')}`

  // Store nonce in DB (TTL index on createdAt handles cleanup)
  await linkNonces().insertOne({
    nonce: challenge,
    userId: req.user.userId,
    createdAt: new Date()
  })

  res.json({ challenge, snapieAccount: process.env.SNAPIE_ACCOUNT })
}))

// POST /api/link/confirm
router.post('/confirm', authMiddleware, csrfMiddleware, asyncMw(async (req, res) => {
  const { username, challenge, signature } = req.body

  if (!username || !challenge || !signature) {
    return res.status(400).json({ error: 'username, challenge, and signature required' })
  }

  // Validate username format
  if (typeof username !== 'string' || username.length < 3 || username.length > 16) {
    return res.status(400).json({ error: 'invalid_username' })
  }

  const user = await getUserById(req.user.userId)
  if (!user) return res.status(401).json({ error: 'Unauthorized' })

  if (user.hiveUsername) {
    return res.status(409).json({ error: 'already_linked' })
  }

  // Verify nonce belongs to this user and hasn't expired (TTL index cleans expired ones)
  const nonceDoc = await linkNonces().findOne({
    nonce: challenge,
    userId: req.user.userId
  })
  if (!nonceDoc) {
    return res.status(400).json({ error: 'invalid_or_expired_challenge' })
  }

  // Consume nonce
  await linkNonces().deleteOne({ nonce: challenge })

  // Verify signature against on-chain posting keys
  const valid = await verifyHiveIdentity(username, challenge, signature)
  if (!valid) {
    return res.status(401).json({ error: 'invalid_signature' })
  }

  // Check that @snapie has posting authority
  const hasAuth = await hasPostingAuthority(username, process.env.SNAPIE_ACCOUNT)
  if (!hasAuth) {
    return res.status(403).json({
      error: 'posting_authority_required',
      instructions: `Add @${process.env.SNAPIE_ACCOUNT} to your account's posting authorities via Hive Keychain or Hivesigner, then try again.`
    })
  }

  // Link the account
  await users().updateOne(
    { _id: user._id },
    {
      $set: {
        hiveUsername: username,
        custodyMode: 'emancipated',
        everHadAccount: true,
        updatedAt: new Date()
      }
    }
  )

  res.json({ ok: true, hiveUsername: username })
}))

export default router
