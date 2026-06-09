import { Router } from 'express'
import { asyncMw } from '../services/async-middleware.js'
import { authMiddleware } from '../services/auth.js'
import { csrfMiddleware } from '../services/csrf.js'
import { broadcastOps, getAccount, hiveErr, isRcError, signMessage } from '../services/hive.js'
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
    if (isRcError(err)) {
      await logOp(user._id, user.hiveUsername, opType, 'posting', user.custodyMode, null, false, 'insufficient_rc', req.ip)
      return res.status(503).json({ error: 'insufficient_rc' })
    }
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
    if (isRcError(err)) {
      await logOp(user._id, user.hiveUsername, opType, 'active', 'custodial', null, false, 'insufficient_rc', req.ip)
      return res.status(503).json({ error: 'insufficient_rc' })
    }
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

// POST /api/hive/limit-order-create
// Places a limit order on the internal HIVE/HBD market.
// sell: what you give up; receive: minimum you'll accept.
// Set fillOrKill: true for an instant market swap (order cancels if not immediately filled).
router.post('/limit-order-create', authMiddleware, csrfMiddleware, asyncMw(async (req, res) => {
  const { sell, receive, fillOrKill = false, expiresInSeconds = 3600, orderId } = req.body

  if (!sell || !/^\d+\.\d{3} (HIVE|HBD)$/.test(sell)) {
    return res.status(400).json({ error: 'invalid_sell' })
  }
  if (!receive || !/^\d+\.\d{3} (HIVE|HBD)$/.test(receive)) {
    return res.status(400).json({ error: 'invalid_receive' })
  }
  const sellCurrency   = sell.split(' ')[1]
  const recvCurrency   = receive.split(' ')[1]
  if (sellCurrency === recvCurrency) {
    return res.status(400).json({ error: 'sell_and_receive_must_differ' })
  }
  if (typeof fillOrKill !== 'boolean') {
    return res.status(400).json({ error: 'invalid_fill_or_kill' })
  }
  const expSecs = Number(expiresInSeconds)
  if (!Number.isInteger(expSecs) || expSecs < 1 || expSecs > 86400 * 30) {
    return res.status(400).json({ error: 'invalid_expires_in_seconds' })
  }

  const oid = orderId !== undefined ? Number(orderId) : Math.floor(Date.now() / 1000) % 0xFFFFFFFF
  if (!Number.isInteger(oid) || oid < 0 || oid > 0xFFFFFFFF) {
    return res.status(400).json({ error: 'invalid_order_id' })
  }

  const expiration = new Date(Date.now() + expSecs * 1000).toISOString().replace(/\.\d{3}Z$/, '')

  await activeOp(req, res, 'limit_order_create', (owner) => (
    ['limit_order_create', {
      owner,
      orderid: oid,
      amount_to_sell: sell,
      min_to_receive: receive,
      fill_or_kill: fillOrKill,
      expiration
    }]
  ))
}))

// POST /api/hive/limit-order-cancel
router.post('/limit-order-cancel', authMiddleware, csrfMiddleware, asyncMw(async (req, res) => {
  const { orderId } = req.body

  const oid = Number(orderId)
  if (!Number.isInteger(oid) || oid < 0 || oid > 0xFFFFFFFF) {
    return res.status(400).json({ error: 'invalid_order_id' })
  }

  await activeOp(req, res, 'limit_order_cancel', (owner) => (
    ['limit_order_cancel', { owner, orderid: oid }]
  ))
}))

// POST /api/hive/transfer-to-savings
router.post('/transfer-to-savings', authMiddleware, csrfMiddleware, asyncMw(async (req, res) => {
  const { to, amount, memo = '' } = req.body

  if (to !== undefined && (typeof to !== 'string' || to.length < 3 || to.length > 16)) {
    return res.status(400).json({ error: 'invalid_to' })
  }
  if (!amount || !/^\d+\.\d{3} (HIVE|HBD)$/.test(amount)) {
    return res.status(400).json({ error: 'invalid_amount' })
  }
  if (typeof memo !== 'string' || memo.length > 2048) {
    return res.status(400).json({ error: 'memo_too_long' })
  }

  await activeOp(req, res, 'transfer_to_savings', (from) => (
    ['transfer_to_savings', { from, to: to || from, amount, memo }]
  ))
}))

// POST /api/hive/transfer-from-savings
// Initiates a savings withdrawal — funds arrive after 3 days.
// requestId must be unique per account; auto-generated from timestamp if omitted.
router.post('/transfer-from-savings', authMiddleware, csrfMiddleware, asyncMw(async (req, res) => {
  const { to, amount, memo = '', requestId } = req.body

  if (to !== undefined && (typeof to !== 'string' || to.length < 3 || to.length > 16)) {
    return res.status(400).json({ error: 'invalid_to' })
  }
  if (!amount || !/^\d+\.\d{3} (HIVE|HBD)$/.test(amount)) {
    return res.status(400).json({ error: 'invalid_amount' })
  }
  if (typeof memo !== 'string' || memo.length > 2048) {
    return res.status(400).json({ error: 'memo_too_long' })
  }

  const reqId = requestId !== undefined ? Number(requestId) : Math.floor(Date.now() / 1000)
  if (!Number.isInteger(reqId) || reqId < 0) {
    return res.status(400).json({ error: 'invalid_request_id' })
  }

  await activeOp(req, res, 'transfer_from_savings', (from) => (
    ['transfer_from_savings', { from, to: to || from, amount, memo, request_id: reqId }]
  ))
}))

// POST /api/hive/convert
// Converts HBD → HIVE via the debt conversion mechanism (~3.5 day wait, median price).
router.post('/convert', authMiddleware, csrfMiddleware, asyncMw(async (req, res) => {
  const { amount, requestId } = req.body

  if (!amount || !/^\d+\.\d{3} HBD$/.test(amount)) {
    return res.status(400).json({ error: 'invalid_amount' })
  }

  const reqId = requestId !== undefined ? Number(requestId) : Math.floor(Date.now() / 1000)
  if (!Number.isInteger(reqId) || reqId < 0) {
    return res.status(400).json({ error: 'invalid_request_id' })
  }

  await activeOp(req, res, 'convert', (owner) => (
    ['convert', { owner, requestid: reqId, amount }]
  ))
}))

// POST /api/hive/collateralized-convert
// Converts HIVE → HBD instantly using collateralized conversion.
// You receive HBD immediately; excess collateral is returned after ~3.5 days.
router.post('/collateralized-convert', authMiddleware, csrfMiddleware, asyncMw(async (req, res) => {
  const { amount, requestId } = req.body

  if (!amount || !/^\d+\.\d{3} HIVE$/.test(amount)) {
    return res.status(400).json({ error: 'invalid_amount' })
  }

  const reqId = requestId !== undefined ? Number(requestId) : Math.floor(Date.now() / 1000)
  if (!Number.isInteger(reqId) || reqId < 0) {
    return res.status(400).json({ error: 'invalid_request_id' })
  }

  await activeOp(req, res, 'collateralized_convert', (owner) => (
    ['collateralized_convert', { owner, requestid: reqId, amount }]
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
    if (isRcError(err)) {
      await logOp(user._id, user.hiveUsername, 'claim_reward_balance', 'posting', user.custodyMode, null, false, 'insufficient_rc', req.ip)
      return res.status(503).json({ error: 'insufficient_rc' })
    }
    const errMsg = hiveErr(err)
    await logOp(user._id, user.hiveUsername, 'claim_reward_balance', 'posting', user.custodyMode, null, false, errMsg, req.ip)
    res.status(500).json({ error: errMsg })
  }
}))

// POST /api/hive/sign-message
// Signs a challenge/message with the user's Hive posting key.
// Custodial: server decrypts and signs silently.
// Emancipated: returns { needsClientSigning: true } — client signs via Keychain/AIOha.
router.post('/sign-message', authMiddleware, csrfMiddleware, asyncMw(async (req, res) => {
  const user = await getUserById(req.user.userId)
  if (!user || !user.hiveUsername) {
    return res.status(403).json({ error: 'no_hive_account' })
  }

  const { message } = req.body
  if (!message || typeof message !== 'string') {
    return res.status(400).json({ error: 'message required' })
  }
  if (message.length > 512) {
    return res.status(400).json({ error: 'message_too_long' })
  }

  if (user.custodyMode === 'emancipated') {
    return res.json({ needsClientSigning: true, message, account: user.hiveUsername })
  }

  if (user.custodyMode !== 'custodial') {
    return res.status(403).json({ error: 'no_custody_mode' })
  }

  try {
    const serverKey = deriveServerKey(user._id.toString())
    const postingWif = decryptKey(user.encryptedKeys.posting, serverKey)
    const signature = signMessage(message, postingWif)
    res.json({ signature, account: user.hiveUsername })
  } catch {
    res.status(500).json({ error: 'signing_failed' })
  }
}))

export default router
