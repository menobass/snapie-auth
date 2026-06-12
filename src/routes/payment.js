import { Router } from 'express'
import { rateLimit } from 'express-rate-limit'
import { asyncMw } from '../services/async-middleware.js'
import { authMiddleware } from '../services/auth.js'
import { csrfMiddleware } from '../services/csrf.js'
import { getAccountCreationFee } from '../services/hive.js'
import { getHivePrice } from '../services/account-value.js'
import { getUserById } from '../services/users.js'
import { paymentIntents } from '../services/db.js'
import {
  createHiveIntent,
  createLightningIntent,
  getIntent
} from '../services/payment.js'

const router = Router()

const intentLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false
})

// GET /api/payment/fee — live witness account creation fee
router.get('/fee', asyncMw(async (_req, res) => {
  const [feeStr, hivePrice] = await Promise.all([getAccountCreationFee(), getHivePrice()])
  const hiveAmount = parseFloat(feeStr)
  res.json({
    amountHive: feeStr,
    amountUsd: +(hiveAmount * hivePrice).toFixed(2)
  })
}))

// POST /api/payment/hive-intent — create a HIVE payment intent
router.post('/hive-intent', authMiddleware, csrfMiddleware, intentLimiter, asyncMw(async (req, res) => {
  const user = await getUserById(req.user.userId)
  if (!user) return res.status(401).json({ error: 'Unauthorized' })
  if (user.hiveUsername) return res.status(409).json({ error: 'already_linked' })

  try {
    const intent = await createHiveIntent(req.user.userId)
    res.status(201).json(intent)
  } catch (err) {
    if (err.code === 'too_many_pending_intents') {
      return res.status(429).json({ error: 'too_many_pending_intents' })
    }
    throw err
  }
}))

// POST /api/payment/lightning-intent — create a Lightning invoice via v4v.app
router.post('/lightning-intent', authMiddleware, csrfMiddleware, intentLimiter, asyncMw(async (req, res) => {
  const user = await getUserById(req.user.userId)
  if (!user) return res.status(401).json({ error: 'Unauthorized' })
  if (user.hiveUsername) return res.status(409).json({ error: 'already_linked' })

  try {
    const intent = await createLightningIntent(req.user.userId)
    res.status(201).json(intent)
  } catch (err) {
    if (err.code === 'too_many_pending_intents') {
      return res.status(429).json({ error: 'too_many_pending_intents' })
    }
    throw err
  }
}))

// GET /api/payment/intent/:memo — poll intent status
router.get('/intent/:memo', authMiddleware, asyncMw(async (req, res) => {
  const intent = await getIntent(req.params.memo, req.user.userId)
  if (!intent) return res.status(404).json({ error: 'not_found' })

  res.json({
    memo: intent._id,
    type: intent.type,
    status: intent.status,
    txId: intent.txId || null,
    amountHive: intent.amountHive,
    amountUsd: intent.amountUsd,
    expiresAt: intent.expiresAt
  })
}))

// GET /api/payment/active — current user's payment status and recent intents
router.get('/active', authMiddleware, asyncMw(async (req, res) => {
  const [user, intents] = await Promise.all([
    getUserById(req.user.userId),
    paymentIntents()
      .find({ userId: req.user.userId, status: { $in: ['pending', 'confirmed'] } })
      .sort({ createdAt: -1 })
      .limit(5)
      .toArray()
  ])

  res.json({
    hasPaidFlag: user?.hasPaidAccountCreation || false,
    intents: intents.map(i => ({
      memo: i._id,
      type: i.type,
      status: i.status,
      amountHive: i.amountHive,
      amountUsd: i.amountUsd,
      txId: i.txId || null,
      createdAt: i.createdAt,
      expiresAt: i.expiresAt
    }))
  })
}))

export default router
