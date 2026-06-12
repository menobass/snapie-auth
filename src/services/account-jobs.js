import crypto from 'crypto'
import { ObjectId } from 'mongodb'
import { accountJobs, users } from './db.js'
import { getAccount, broadcastOps, hiveErr, isValidHivePubKey, PrivateKey } from './hive.js'
import { generateAndEncryptKeys } from './key-crypto.js'

const SNAPIE = () => process.env.SNAPIE_ACCOUNT
const ACTIVE_KEY = () => process.env.SNAPIE_ACTIVE_KEY
const POSTING_KEY = () => process.env.SNAPIE_POSTING_KEY
const RC_BN = () => Math.round(parseFloat(process.env.RC_DELEGATION_BN || '5') * 1e9)
const JOB_TTL_MS = 30 * 60 * 1000 // 30 min
const MAX_ATTEMPTS = 3

// Hive username format: 3-16 chars, lowercase letters/digits/hyphens/dots,
// no consecutive hyphens, each segment (split by .) must be >= 3 chars starting with a letter
export function isValidHiveUsername(username) {
  if (typeof username !== 'string') return false
  if (username.length < 3 || username.length > 16) return false
  if (!/^[a-z0-9][a-z0-9\-.]*[a-z0-9]$/.test(username)) return false
  if (/--/.test(username)) return false
  const segments = username.split('.')
  return segments.every(s => s.length >= 3 && /^[a-z]/.test(s))
}

export async function checkUsernameAvailability(username) {
  if (!isValidHiveUsername(username)) {
    return { available: false, error: 'invalid_format' }
  }
  // Check in-flight reservations
  const existing = await accountJobs().findOne({
    liveUsername: username,
    status: { $in: ['pending', 'broadcasting', 'acked'] }
  })
  if (existing) return { available: false, error: 'reserved' }

  // Check on-chain
  const account = await getAccount(username)
  if (account) return { available: false, error: 'taken' }

  return { available: true, error: null }
}

export async function createJob({ userId, username, custodyMode, ownerPub, activePub, postingPub, memoPub, sponsorTokenId = null, provisionNote = null, returnKeysOnce = false, hasPaidCreation = false }) {
  const jobId = crypto.randomUUID()
  const now = new Date()

  let keys
  if (custodyMode === 'custodial') {
    // Server generates and encrypts all keypairs — user never touches private keys.
    // All keys are derived from a single master password (also encrypted & stored).
    keys = generateAndEncryptKeys(userId, username)
  } else {
    // Emancipated: browser provided public keys, no server-side private key storage
    keys = { ownerPub, activePub, postingPub, memoPub, encryptedKeys: null, encryptedMasterPassword: null }
  }

  const job = {
    _id: jobId,
    userId: new ObjectId(userId),
    username,
    liveUsername: username,
    ownerPub: keys.ownerPub,
    activePub: keys.activePub,
    postingPub: keys.postingPub,
    memoPub: keys.memoPub,
    custodyMode,
    encryptedKeys: keys.encryptedKeys,
    encryptedMasterPassword: keys.encryptedMasterPassword,
    sponsorTokenId: sponsorTokenId || null,
    provisionNote: provisionNote || null,
    returnKeysOnce,
    hasPaidCreation,
    status: 'pending',
    txId: null,
    ackAt: null,
    confirmedAt: null,
    failedAt: null,
    lastError: null,
    attempts: 0,
    createdAt: now,
    expiresAt: new Date(now.getTime() + JOB_TTL_MS)
  }
  await accountJobs().insertOne(job)
  return job
}

export async function getJobForUser(jobId, userId) {
  return accountJobs().findOne({
    _id: jobId,
    userId: new ObjectId(userId)
  })
}

function postingAuthorityMatches(postingAuth, expectedPostingPub, snapieAccount) {
  if (!postingAuth) return false
  const ka = postingAuth.key_auths || []
  const aa = postingAuth.account_auths || []
  const hasPostingPub = ka.length === 1 && ka[0][0] === expectedPostingPub && Number(ka[0][1]) >= 1
  const hasSnapie = aa.some(([acc]) => acc === snapieAccount)
  return hasPostingPub && hasSnapie
}

function plainAuthorityMatches(authObj, expectedPub) {
  if (!authObj) return false
  if ((authObj.account_auths || []).length !== 0) return false
  const ka = authObj.key_auths || []
  return ka.length === 1 && ka[0][0] === expectedPub && Number(ka[0][1]) >= 1
}

async function failJob(job, reason) {
  await accountJobs().updateOne(
    { _id: job._id },
    {
      $set: { status: 'failed', failedAt: new Date(), lastError: reason },
      $unset: { liveUsername: '' }
    }
  )
  // Restore paid flag so user can retry without paying again
  if (job.hasPaidCreation) {
    await users().updateOne({ _id: job.userId }, { $set: { hasPaidAccountCreation: true } })
  }
}

async function sleep(ms) {
  return new Promise(r => setTimeout(r, ms))
}

export async function delegateRc(username) {
  const op = ['custom_json', {
    required_auths: [],
    required_posting_auths: [SNAPIE()],
    id: 'rc',
    json: JSON.stringify(['delegate_rc', {
      from: SNAPIE(),
      delegatees: [username],
      max_rc: RC_BN()
    }])
  }]
  for (let i = 1; i <= 4; i++) {
    try {
      const r = await broadcastOps([op], POSTING_KEY())
      return { ok: true, txId: r.id }
    } catch (e) {
      if (i === 4) return { ok: false, error: e.message }
      await sleep(2000 * i)
    }
  }
}

export async function broadcastAccountCreate(job) {
  await accountJobs().updateOne(
    { _id: job._id },
    { $set: { status: 'broadcasting', attempts: job.attempts + 1 } }
  )

  const op = ['create_claimed_account', {
    creator: SNAPIE(),
    new_account_name: job.username,
    owner:   { weight_threshold: 1, account_auths: [], key_auths: [[job.ownerPub, 1]] },
    active:  { weight_threshold: 1, account_auths: [], key_auths: [[job.activePub, 1]] },
    posting: {
      weight_threshold: 1,
      account_auths: [[SNAPIE(), 1]],
      key_auths: [[job.postingPub, 1]]
    },
    memo_key: job.memoPub,
    json_metadata: JSON.stringify({ app: 'snapie', created_via: 'snapie-auth' }),
    extensions: []
  }]

  try {
    const result = await broadcastOps([op], ACTIVE_KEY())
    await accountJobs().updateOne(
      { _id: job._id },
      { $set: { status: 'acked', txId: result.id, ackAt: new Date() } }
    )
    // Try to confirm 4s after broadcast without waiting for next reconcile tick
    setTimeout(() => confirmAckedJob({ ...job, status: 'acked', txId: result.id, ackAt: new Date() }).catch(() => {}), 4000)
  } catch (err) {
    const reason = hiveErr(err)
    if (job.attempts + 1 >= MAX_ATTEMPTS) {
      await failJob(job, reason)
    } else {
      await accountJobs().updateOne(
        { _id: job._id },
        { $set: { status: 'pending', lastError: reason } }
      )
    }
  }
}

export async function confirmAckedJob(job) {
  const account = await getAccount(job.username)
  if (!account) {
    // Give 90s grace period after ack for blocks to settle
    if (Date.now() - new Date(job.ackAt).getTime() > 90000) {
      await failJob(job, 'acked_but_account_absent')
    }
    return
  }

  const ok =
    plainAuthorityMatches(account.owner, job.ownerPub) &&
    plainAuthorityMatches(account.active, job.activePub) &&
    postingAuthorityMatches(account.posting, job.postingPub, SNAPIE()) &&
    account.memo_key === job.memoPub

  if (!ok) {
    await failJob(job, 'account_keys_mismatch')
    return
  }

  // Delegate RC — mandatory
  await delegateRc(job.username)

  await accountJobs().updateOne(
    { _id: job._id, status: 'acked' },
    {
      $set: { status: 'confirmed', confirmedAt: new Date() },
      $unset: { liveUsername: '' }
    }
  )

  await users().updateOne(
    { _id: job.userId },
    {
      $set: {
        hiveUsername: job.username,
        custodyMode: job.custodyMode,
        encryptedKeys: job.custodyMode === 'custodial' ? job.encryptedKeys : null,
        encryptedMasterPassword: job.custodyMode === 'custodial' ? (job.encryptedMasterPassword || null) : null,
        everHadAccount: true,
        updatedAt: new Date()
      }
    }
  )
}

export async function reconcileTick() {
  try {
    // 1. Expire stale jobs — restore hasPaidCreation flag first so users can retry
    const now = new Date()
    const expiringPaid = await accountJobs()
      .find({ status: { $in: ['pending', 'broadcasting', 'acked'] }, expiresAt: { $lt: now }, hasPaidCreation: true })
      .toArray()
    for (const job of expiringPaid) {
      await users().updateOne({ _id: job.userId }, { $set: { hasPaidAccountCreation: true } })
    }
    await accountJobs().updateMany(
      { status: { $in: ['pending', 'broadcasting', 'acked'] }, expiresAt: { $lt: now } },
      { $set: { status: 'expired', failedAt: now }, $unset: { liveUsername: '' } }
    )

    // 2. Pick up pending jobs (limit 5 per tick)
    const pending = await accountJobs().find({ status: 'pending' }).limit(5).toArray()
    for (const job of pending) {
      await broadcastAccountCreate(job)
    }

    // 3. Verify acked jobs on-chain
    const acked = await accountJobs().find({ status: 'acked' }).toArray()
    for (const job of acked) {
      await confirmAckedJob(job)
    }
  } catch (err) {
    console.error('reconcileTick error:', err.message)
  }
}

export function startReconcileLoop() {
  const interval = parseInt(process.env.ACCOUNT_RECONCILE_INTERVAL_MS || '5000', 10)
  setInterval(reconcileTick, interval)
  console.log(`Account reconcile loop started (every ${interval}ms)`)
}
