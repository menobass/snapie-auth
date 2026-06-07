import { Router } from 'express'
import crypto from 'crypto'
import { asyncMw } from '../services/async-middleware.js'
import { createJob, getJobForUser, isValidHiveUsername, checkUsernameAvailability } from '../services/account-jobs.js'
import { isValidHivePubKey, getAccount } from '../services/hive.js'
import { issueToken } from '../services/sponsor-tokens.js'
import { users, accountJobs } from '../services/db.js'
import { hashEmail, upsertUser } from '../services/users.js'
import { deriveServerKey, decryptKey } from '../services/key-crypto.js'
import { ObjectId } from 'mongodb'

const router = Router()

// Bearer token auth for internal/service-to-service calls
router.use((req, res, next) => {
  const key = process.env.INTERNAL_API_KEY
  if (!key) return res.status(503).json({ error: 'internal_api_not_configured' })

  const auth = req.headers.authorization || ''
  if (!auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' })

  const provided = auth.slice(7)
  try {
    if (!crypto.timingSafeEqual(Buffer.from(provided), Buffer.from(key))) {
      return res.status(401).json({ error: 'Unauthorized' })
    }
  } catch {
    return res.status(401).json({ error: 'Unauthorized' })
  }
  next()
})

// POST /api/internal/provision-account
// Creates a Hive account directly, no Google session required.
// Useful for: selling accounts, gifting, admin provisioning.
//
// Body:
//   username        string   required
//   custodyMode     'custodial' | 'emancipated'   required
//   ownerPub etc.   string   required only for emancipated
//   linkedEmail     string   optional — links to existing snapie-auth user by email
//   returnKeysOnce  boolean  custodial only — return keys on first poll, then wipe
//   note            string   optional — stored for audit purposes
//
// Returns: { jobId } immediately. Poll GET /api/internal/jobs/:jobId for status + keys.
router.post('/provision-account', asyncMw(async (req, res) => {
  const { username, custodyMode, ownerPub, activePub, postingPub, memoPub,
          linkedEmail, returnKeysOnce = false, note = null } = req.body

  if (!isValidHiveUsername(username)) {
    return res.status(400).json({ error: 'invalid_username' })
  }
  if (!['custodial', 'emancipated'].includes(custodyMode)) {
    return res.status(400).json({ error: 'invalid_custody_mode' })
  }
  if (custodyMode === 'emancipated') {
    for (const [name, key] of Object.entries({ ownerPub, activePub, postingPub, memoPub })) {
      if (!key || !isValidHivePubKey(key)) {
        return res.status(400).json({ error: `invalid_pubkey: ${name}` })
      }
    }
    if (new Set([ownerPub, activePub, postingPub, memoPub]).size !== 4) {
      return res.status(400).json({ error: 'duplicate_pubkeys' })
    }
  }

  const avail = await checkUsernameAvailability(username)
  if (!avail.available) return res.status(409).json({ error: avail.error })

  const snapieAccount = await getAccount(process.env.SNAPIE_ACCOUNT)
  if (!snapieAccount || (snapieAccount.pending_claimed_accounts || 0) === 0) {
    return res.status(503).json({ error: 'no_acts' })
  }

  // Resolve or create a user to own this account
  let userId
  if (linkedEmail) {
    const emailHash = hashEmail(linkedEmail)
    // Try to find existing user by email
    const existing = await users().findOne({ emailHash })
    if (existing) {
      userId = existing._id.toString()
    } else {
      // Create a placeholder user — can be claimed later via Google login
      const placeholder = await upsertUser({
        provider: 'provisioned',
        providerId: crypto.randomUUID(),
        emailHash,
        name: null,
        picture: null
      })
      userId = placeholder._id.toString()
    }
  } else {
    // No email — create anonymous placeholder
    const placeholder = await upsertUser({
      provider: 'provisioned',
      providerId: crypto.randomUUID(),
      emailHash: null,
      name: null,
      picture: null
    })
    userId = placeholder._id.toString()
  }

  const job = await createJob({
    userId,
    username,
    custodyMode,
    ownerPub, activePub, postingPub, memoPub,
    returnKeysOnce: custodyMode === 'custodial' && returnKeysOnce,
    provisionNote: note
  })

  res.status(201).json({ jobId: job._id, userId })
}))

// GET /api/internal/jobs/:jobId
// Poll provisioned job status.
// If returnKeysOnce was set and status is 'confirmed', decrypts and returns keys once,
// then wipes them (sets custodyMode to emancipated).
router.get('/jobs/:jobId', asyncMw(async (req, res) => {
  const job = await accountJobs().findOne({ _id: req.params.jobId })
  if (!job) return res.status(404).json({ error: 'not_found' })

  const base = {
    jobId: job._id,
    username: job.username,
    status: job.status,
    custodyMode: job.custodyMode,
    txId: job.txId || null,
    error: job.lastError || null
  }

  // Return keys once if requested and job is confirmed
  if (job.returnKeysOnce && job.status === 'confirmed') {
    const user = await users().findOne({ _id: job.userId })

    if (!user?.encryptedKeys) {
      // Already wiped — keys were already returned
      return res.json({ ...base, keysAlreadyDelivered: true })
    }

    const serverKey = deriveServerKey(user._id.toString())
    let keys
    try {
      keys = {
        owner:   decryptKey(user.encryptedKeys.owner,   serverKey),
        active:  decryptKey(user.encryptedKeys.active,  serverKey),
        posting: decryptKey(user.encryptedKeys.posting, serverKey),
        memo:    decryptKey(user.encryptedKeys.memo,    serverKey)
      }
    } catch {
      return res.status(500).json({ error: 'key_decryption_failed' })
    }

    // Wipe immediately — one-shot delivery
    await users().updateOne(
      { _id: user._id },
      { $set: { custodyMode: 'emancipated', encryptedKeys: null, emancipatedAt: new Date(), updatedAt: new Date() } }
    )

    return res.json({ ...base, keys })
  }

  res.json(base)
}))

// POST /api/internal/issue-sponsor-token
// External app calls this when a user has earned a free account.
// The token is tied to their email and redeemed automatically on registration.
//
// Body:
//   email           string   required
//   note            string   optional  e.g. "earned 500 credits on credits-app"
//   expiresInDays   number   optional  default: no expiry
router.post('/issue-sponsor-token', asyncMw(async (req, res) => {
  const { email, note = null, expiresInDays = null } = req.body

  if (!email || typeof email !== 'string' || !email.includes('@')) {
    return res.status(400).json({ error: 'valid email required' })
  }

  const token = await issueToken({
    email,
    note,
    issuedBy: 'internal-api',
    expiresInDays: expiresInDays ? Number(expiresInDays) : null
  })

  res.status(201).json({ tokenId: token._id, email, note: token.note, expiresAt: token.expiresAt })
}))

export default router
