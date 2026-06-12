import crypto from 'crypto'
import { ObjectId } from 'mongodb'
import { paymentIntents, users } from './db.js'
import { getAccountCreationFee, client } from './hive.js'
import { getHivePrice } from './account-value.js'

const RECEIVING_ACCOUNT = () =>
  process.env.SNAPIE_RECEIVING_ACCOUNT || process.env.SNAPIE_ACCOUNT || ''
const LIGHTNING_HIVE_ACCOUNT = () =>
  process.env.SNAPIE_LIGHTNING_HIVE_ACCOUNT || RECEIVING_ACCOUNT()
const V4V_RECEIVE_CURRENCY = () => process.env.V4V_RECEIVE_CURRENCY || 'hive'
const INTENT_EXPIRY_MS = 30 * 60 * 1000
const POLL_INTERVAL_MS = 5000
const MAX_PENDING_INTENTS_PER_USER = 3
const PAYMENT_TOLERANCE = 0.95  // accept down to 95% of expected (covers Lightning slippage)

async function checkPendingIntentCap(userId, purpose) {
  const count = await paymentIntents().countDocuments({ userId, purpose, status: 'pending' })
  if (count >= MAX_PENDING_INTENTS_PER_USER) {
    throw Object.assign(new Error('too_many_pending_intents'), { code: 'too_many_pending_intents' })
  }
}

export async function createHiveIntent(userId) {
  await checkPendingIntentCap(userId, 'account_creation')
  const [feeStr, hivePrice] = await Promise.all([getAccountCreationFee(), getHivePrice()])
  const hiveAmount = parseFloat(feeStr)
  const amountUsd = +(hiveAmount * hivePrice).toFixed(2)
  const memo = crypto.randomUUID()
  const now = new Date()
  const expiresAt = new Date(now.getTime() + INTENT_EXPIRY_MS)

  await paymentIntents().insertOne({
    _id: memo,
    userId,
    type: 'hive',
    purpose: 'account_creation',
    amountHive: feeStr,
    amountUsd,
    lightningInvoice: null,
    status: 'pending',
    txId: null,
    createdAt: now,
    expiresAt,
    confirmedAt: null
  })

  return { memo, receivingAccount: RECEIVING_ACCOUNT(), amount: feeStr, amountUsd, expiresAt }
}

export async function createLightningIntent(userId) {
  await checkPendingIntentCap(userId, 'account_creation')
  const [feeStr, hivePrice] = await Promise.all([getAccountCreationFee(), getHivePrice()])
  const hiveAmount = parseFloat(feeStr)
  const amountUsd = +(hiveAmount * hivePrice).toFixed(2)
  const memo = crypto.randomUUID()
  const now = new Date()
  const expiresAt = new Date(now.getTime() + INTENT_EXPIRY_MS)

  const res = await fetch('https://api.v4v.app/v1/new_invoice_hive', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      hive_accname: LIGHTNING_HIVE_ACCOUNT(),
      amount: amountUsd,
      currency: 'USD',
      receive_currency: V4V_RECEIVE_CURRENCY(),
      app_name: 'snapie',
      expiry: '1800',
      message: memo,
      qr_code: 'true'
    }),
    signal: AbortSignal.timeout(10000)
  })

  if (!res.ok) {
    const text = await res.text()
    throw new Error(`v4v.app error ${res.status}: ${text.slice(0, 200)}`)
  }

  const data = await res.json()
  const invoice = data.payment_request
  if (!invoice) throw new Error('v4v.app returned no payment_request')

  await paymentIntents().insertOne({
    _id: memo,
    userId,
    type: 'lightning',
    purpose: 'account_creation',
    amountHive: feeStr,
    amountUsd,
    lightningInvoice: invoice,
    status: 'pending',
    txId: null,
    createdAt: now,
    expiresAt,
    confirmedAt: null
  })

  return { memo, invoice, amountUsd, expiresAt }
}

export async function getIntent(memo, userId) {
  return paymentIntents().findOne({ _id: memo, userId })
}

export async function pollPendingIntents() {
  const account = RECEIVING_ACCOUNT()
  if (!account) return

  const pending = await paymentIntents().find({ status: 'pending' }).toArray()
  if (!pending.length) return

  let history
  try {
    history = await client.database.call('get_account_history', [account, -1, 1000])
  } catch (err) {
    console.error('payment poll: get_account_history failed:', err.message)
    return
  }

  for (const [, entry] of history) {
    const [opType, opData] = entry.op
    if (opType !== 'transfer') continue
    if (opData.to !== account) continue

    const entryMemo = opData.memo || ''
    const matched = pending.find(intent => entryMemo.includes(intent._id))
    if (!matched) continue

    if (matched.type === 'lightning' && opData.from !== 'v4vapp') continue

    // Reject underpayment — allow 5% slippage for Lightning conversion
    const sentAmount = parseFloat(opData.amount)
    const expectedAmount = parseFloat(matched.amountHive)
    if (sentAmount < expectedAmount * PAYMENT_TOLERANCE) {
      console.warn(`payment: underpayment for intent ${matched._id} — expected ${matched.amountHive}, got ${opData.amount}`)
      continue
    }

    await confirmIntent(matched, entry.trx_id)
  }
}

async function confirmIntent(intent, txId) {
  const result = await paymentIntents().updateOne(
    { _id: intent._id, status: 'pending' },
    { $set: { status: 'confirmed', txId, confirmedAt: new Date() } }
  )
  if (result.modifiedCount === 0) return

  console.log(`payment confirmed: ${intent._id} type=${intent.type} user=${intent.userId}`)

  if (intent.purpose === 'account_creation') {
    await users().updateOne(
      { _id: new ObjectId(intent.userId) },
      { $set: { hasPaidAccountCreation: true } }
    )
  }
}

export function startPaymentPollLoop() {
  async function tick() {
    try {
      await pollPendingIntents()
    } catch (err) {
      console.error('payment poll error:', err.message)
    }
    setTimeout(tick, POLL_INTERVAL_MS)
  }
  setTimeout(tick, POLL_INTERVAL_MS)
}
