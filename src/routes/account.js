import { Router } from 'express'
import { asyncMw } from '../services/async-middleware.js'
import { authMiddleware } from '../services/auth.js'
import { csrfMiddleware } from '../services/csrf.js'
import { getUserById, clearPaidAccountCreation } from '../services/users.js'
import {
  checkUsernameAvailability,
  createJob,
  getJobForUser,
  isValidHiveUsername
} from '../services/account-jobs.js'
import { isValidHivePubKey, getAccount } from '../services/hive.js'
import { getAccountValue, isEmancipationRequired } from '../services/account-value.js'
import { findValidToken, consumeToken } from '../services/sponsor-tokens.js'
import { checkFreeQuota, consumeFreeQuota } from '../services/free-quota.js'

const router = Router()

// GET /api/account/eligibility
router.get('/eligibility', authMiddleware, asyncMw(async (req, res) => {
  const user = await getUserById(req.user.userId)
  if (!user) return res.status(401).json({ error: 'Unauthorized' })

  if (user.hiveUsername) {
    return res.json({ canCreate: false, canLinkExisting: false, reason: 'already_linked' })
  }

  // Check if user has a sponsor token — overrides previously_had_account restriction
  let sponsorToken = null
  if (user.emailHash) {
    sponsorToken = await findValidToken(user.emailHash)
  }

  const hasPaid = user.hasPaidAccountCreation || false

  if (user.everHadAccount && !sponsorToken && !hasPaid) {
    return res.json({ canCreate: false, canLinkExisting: true, reason: 'previously_had_account' })
  }

  if (!sponsorToken && !hasPaid) {
    const quota = await checkFreeQuota(req.ip)
    if (!quota.allowed) {
      return res.json({ canCreate: false, canLinkExisting: true, reason: quota.reason })
    }
  }

  let hasActs = false
  try {
    const snapieAccount = await getAccount(process.env.SNAPIE_ACCOUNT)
    hasActs = snapieAccount && (snapieAccount.pending_claimed_accounts || 0) > 0
  } catch {
    hasActs = false
  }

  if (!hasActs) {
    return res.json({ canCreate: false, canLinkExisting: true, reason: 'no_acts' })
  }

  res.json({
    canCreate: true,
    canLinkExisting: true,
    reason: null,
    sponsored: !!sponsorToken,
    alreadyPaid: hasPaid
  })
}))

// GET /api/account/check-username/:username
router.get('/check-username/:username', authMiddleware, asyncMw(async (req, res) => {
  const result = await checkUsernameAvailability(req.params.username)
  res.json(result)
}))

// POST /api/account/create
router.post('/create', authMiddleware, csrfMiddleware, asyncMw(async (req, res) => {
  const user = await getUserById(req.user.userId)
  if (!user) return res.status(401).json({ error: 'Unauthorized' })

  if (user.hiveUsername) return res.status(409).json({ error: 'already_linked' })

  // Check for sponsor token before enforcing previously_had_account
  let sponsorToken = null
  if (user.emailHash) {
    sponsorToken = await findValidToken(user.emailHash)
  }

  const hasPaid = user.hasPaidAccountCreation || false

  if (user.everHadAccount && !sponsorToken && !hasPaid) {
    return res.status(403).json({ error: 'previously_had_account' })
  }

  if (!sponsorToken && !hasPaid) {
    const quota = await consumeFreeQuota(req.ip)
    if (!quota.allowed) {
      return res.status(429).json({ error: quota.reason })
    }
  }

  const { username, custodyMode, ownerPub, activePub, postingPub, memoPub } = req.body

  if (!isValidHiveUsername(username)) {
    return res.status(400).json({ error: 'invalid_username' })
  }

  if (!['custodial', 'emancipated'].includes(custodyMode)) {
    return res.status(400).json({ error: 'invalid_custody_mode' })
  }

  if (custodyMode === 'emancipated') {
    const pubkeys = { ownerPub, activePub, postingPub, memoPub }
    for (const [name, key] of Object.entries(pubkeys)) {
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

  const job = await createJob({
    userId: user._id.toString(),
    username,
    custodyMode,
    ownerPub, activePub, postingPub, memoPub,
    sponsorTokenId: sponsorToken?._id || null,
    hasPaidCreation: hasPaid
  })

  // Consume the sponsor token atomically now that the job is queued
  if (sponsorToken) {
    await consumeToken(sponsorToken._id, user._id)
  } else if (hasPaid) {
    await clearPaidAccountCreation(user._id.toString())
  }

  res.status(201).json({
    jobId: job._id,
    sponsored: !!sponsorToken || hasPaid
  })
}))

// GET /api/account/job/:jobId
router.get('/job/:jobId', authMiddleware, asyncMw(async (req, res) => {
  const job = await getJobForUser(req.params.jobId, req.user.userId)
  if (!job) return res.status(404).json({ error: 'not_found' })

  res.json({
    jobId: job._id,
    username: job.username,
    status: job.status,
    txId: job.txId || null,
    error: job.lastError || null
  })
}))

// GET /api/account/value
router.get('/value', authMiddleware, asyncMw(async (req, res) => {
  const user = await getUserById(req.user.userId)
  if (!user) return res.status(401).json({ error: 'Unauthorized' })
  if (!user.hiveUsername) return res.status(400).json({ error: 'no_hive_account' })

  const value = await getAccountValue(user.hiveUsername)
  if (!value) return res.status(404).json({ error: 'account_not_found' })

  const emancipationRequired = isEmancipationRequired(user.custodyMode, value.totalValueUsd)
  res.json({ ...value, emancipationRequired })
}))

export default router
