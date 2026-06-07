import { Router } from 'express'
import { asyncMw } from '../services/async-middleware.js'
import { authMiddleware } from '../services/auth.js'
import { csrfMiddleware } from '../services/csrf.js'
import { broadcastOps, getAccount, hiveErr } from '../services/hive.js'
import { getUserById } from '../services/users.js'
import { deriveServerKey, decryptKey } from '../services/key-crypto.js'
import { broadcastLog } from '../services/db.js'
import { ObjectId } from 'mongodb'

const router = Router()

const POSTING_OPS = new Set([
  'vote', 'comment', 'delete_comment', 'custom_json', 'claim_reward_balance'
])

const NEVER_SIGN = new Set([
  'account_update', 'account_update2', 'recover_account',
  'witness_update', 'witness_vote', 'feed_publish',
  'account_witness_vote', 'account_witness_proxy',
  'proposal_create', 'proposal_delete', 'update_proposal_votes'
])

async function logOp(userId, hiveUsername, opType, opClass, custodyMode, txId, success, error, ip) {
  await broadcastLog().insertOne({
    userId: new ObjectId(userId),
    hiveUsername,
    opType,
    opClass,
    custodyMode,
    txId: txId || null,
    success,
    error: error || null,
    ip,
    createdAt: new Date()
  }).catch(() => {})
}

// Resolve active key for custodial users using server-side key derivation
function getCustodialActiveKey(user) {
  if (!user.encryptedKeys?.active) throw new Error('no_encrypted_keys')
  const serverKey = deriveServerKey(user._id.toString())
  return decryptKey(user.encryptedKeys.active, serverKey)
}

// POST /api/hive/broadcast — posting-level ops, all users
router.post('/broadcast', authMiddleware, csrfMiddleware, asyncMw(async (req, res) => {
  const user = await getUserById(req.user.userId)
  if (!user || !user.hiveUsername) {
    return res.status(403).json({ error: 'no_hive_account' })
  }

  const { op } = req.body
  if (!Array.isArray(op) || op.length !== 2 || typeof op[0] !== 'string') {
    return res.status(400).json({ error: 'invalid_op' })
  }

  const opType = op[0]
  if (NEVER_SIGN.has(opType) || !POSTING_OPS.has(opType)) {
    return res.status(403).json({ error: 'op_not_allowed' })
  }

  try {
    const result = await broadcastOps([op], process.env.SNAPIE_POSTING_KEY)
    await logOp(user._id, user.hiveUsername, opType, 'posting', user.custodyMode, result.id, true, null, req.ip)
    res.json({ txId: result.id })
  } catch (err) {
    const errMsg = hiveErr(err)
    await logOp(user._id, user.hiveUsername, opType, 'posting', user.custodyMode, null, false, errMsg, req.ip)
    res.status(500).json({ error: errMsg })
  }
}))

// Shared handler for active-level ops
// Custodial: server decrypts key silently — no password prompt ever
// Emancipated: return unsigned op for client to sign via Keychain/AIOha
async function activeOp(req, res, opType, buildOp) {
  const user = await getUserById(req.user.userId)
  if (!user || !user.hiveUsername) {
    return res.status(403).json({ error: 'no_hive_account' })
  }

  let op
  try {
    op = buildOp(user.hiveUsername)
  } catch (err) {
    return res.status(400).json({ error: err.message })
  }

  if (user.custodyMode === 'emancipated') {
    return res.json({ needsClientSigning: true, unsignedOp: op })
  }

  if (user.custodyMode !== 'custodial') {
    return res.status(403).json({ error: 'no_custody_mode' })
  }

  try {
    const activeWif = getCustodialActiveKey(user)
    const result = await broadcastOps([op], activeWif)
    await logOp(user._id, user.hiveUsername, opType, 'active', 'custodial', result.id, true, null, req.ip)
    res.json({ txId: result.id })
  } catch (err) {
    const errMsg = hiveErr(err)
    await logOp(user._id, user.hiveUsername, opType, 'active', user.custodyMode, null, false, errMsg, req.ip)
    res.status(500).json({ error: errMsg })
  }
}

// POST /api/hive/transfer
router.post('/transfer', authMiddleware, csrfMiddleware, asyncMw(async (req, res) => {
  const { to, amount, memo = '' } = req.body

  if (!to || typeof to !== 'string' || to.length < 3 || to.length > 16) {
    return res.status(400).json({ error: 'invalid_to' })
  }
  if (!amount || !/^\d+\.\d{3} (HIVE|HBD)$/.test(amount)) {
    return res.status(400).json({ error: 'invalid_amount' })
  }
  if (typeof memo !== 'string' || memo.length > 2048) {
    return res.status(400).json({ error: 'memo_too_long' })
  }

  await activeOp(req, res, 'transfer', (from) => (
    ['transfer', { from, to, amount, memo }]
  ))
}))

// POST /api/hive/power-up
router.post('/power-up', authMiddleware, csrfMiddleware, asyncMw(async (req, res) => {
  const { amount } = req.body
  if (!amount || !/^\d+\.\d{3} HIVE$/.test(amount)) {
    return res.status(400).json({ error: 'invalid_amount' })
  }
  await activeOp(req, res, 'transfer_to_vesting', (from) => (
    ['transfer_to_vesting', { from, to: from, amount }]
  ))
}))

// POST /api/hive/power-down
router.post('/power-down', authMiddleware, csrfMiddleware, asyncMw(async (req, res) => {
  const { amount } = req.body
  if (!amount || !/^\d+\.\d{6} VESTS$/.test(amount)) {
    return res.status(400).json({ error: 'invalid_amount' })
  }
  await activeOp(req, res, 'withdraw_vesting', (account) => (
    ['withdraw_vesting', { account, vesting_shares: amount }]
  ))
}))

// POST /api/hive/delegate
router.post('/delegate', authMiddleware, csrfMiddleware, asyncMw(async (req, res) => {
  const { delegatee, amount } = req.body
  if (!delegatee || typeof delegatee !== 'string') {
    return res.status(400).json({ error: 'invalid_delegatee' })
  }
  if (!amount || !/^\d+\.\d{6} VESTS$/.test(amount)) {
    return res.status(400).json({ error: 'invalid_amount' })
  }
  await activeOp(req, res, 'delegate_vesting_shares', (delegator) => (
    ['delegate_vesting_shares', { delegator, delegatee, vesting_shares: amount }]
  ))
}))

// POST /api/hive/claim-rewards — posting-level, all users
router.post('/claim-rewards', authMiddleware, csrfMiddleware, asyncMw(async (req, res) => {
  const user = await getUserById(req.user.userId)
  if (!user || !user.hiveUsername) {
    return res.status(403).json({ error: 'no_hive_account' })
  }

  const account = await getAccount(user.hiveUsername)
  if (!account) return res.status(404).json({ error: 'account_not_found' })

  const op = ['claim_reward_balance', {
    account: user.hiveUsername,
    reward_hive: account.reward_hive_balance,
    reward_hbd: account.reward_hbd_balance,
    reward_vests: account.reward_vesting_balance
  }]

  try {
    const result = await broadcastOps([op], process.env.SNAPIE_POSTING_KEY)
    await logOp(user._id, user.hiveUsername, 'claim_reward_balance', 'posting', user.custodyMode, result.id, true, null, req.ip)
    res.json({ txId: result.id })
  } catch (err) {
    const errMsg = hiveErr(err)
    await logOp(user._id, user.hiveUsername, 'claim_reward_balance', 'posting', user.custodyMode, null, false, errMsg, req.ip)
    res.status(500).json({ error: errMsg })
  }
}))

export default router
