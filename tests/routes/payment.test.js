import { describe, it, expect, vi, beforeEach } from 'vitest'
import request from 'supertest'
import express from 'express'
import { rateLimit } from 'express-rate-limit'

// Mock the payment service
vi.mock('../../src/services/payment.js', () => ({
  createHiveIntent: vi.fn(),
  createLightningIntent: vi.fn(),
  getIntent: vi.fn(),
  startPaymentPollLoop: vi.fn()
}))

// Mock hive and account-value for the fee endpoint
vi.mock('../../src/services/hive.js', () => ({
  getAccountCreationFee: vi.fn().mockResolvedValue('3.000 HIVE'),
  client: { database: { call: vi.fn() } }
}))

vi.mock('../../src/services/account-value.js', () => ({
  getHivePrice: vi.fn().mockResolvedValue(0.4)
}))

// Mock auth middleware — inject a fake user
vi.mock('../../src/services/auth.js', () => ({
  authMiddleware: (req, _res, next) => {
    req.user = { userId: 'user123', type: 'session' }
    next()
  }
}))

vi.mock('../../src/services/csrf.js', () => ({
  csrfMiddleware: (_req, _res, next) => next()
}))

vi.mock('../../src/services/users.js', () => ({
  getUserById: vi.fn().mockResolvedValue({ _id: 'user123', hasPaidAccountCreation: false })
}))

vi.mock('../../src/services/db.js', () => ({
  paymentIntents: () => ({
    find: vi.fn().mockReturnValue({ sort: vi.fn().mockReturnValue({ limit: vi.fn().mockReturnValue({ toArray: vi.fn().mockResolvedValue([]) }) }) }),
    findOne: vi.fn()
  }),
  users: () => ({ updateOne: vi.fn() })
}))

const payment = await import('../../src/services/payment.js')
const paymentRoutes = (await import('../../src/routes/payment.js')).default

// Minimal test app — disable rate limiter for tests
const app = express()
app.use(express.json())
app.use('/api/payment', paymentRoutes)

beforeEach(() => vi.clearAllMocks())

describe('GET /api/payment/fee', () => {
  it('returns amountHive and amountUsd', async () => {
    const res = await request(app).get('/api/payment/fee')
    expect(res.status).toBe(200)
    expect(res.body.amountHive).toBe('3.000 HIVE')
    expect(res.body.amountUsd).toBe(1.2)
  })
})

describe('POST /api/payment/hive-intent', () => {
  it('creates an intent and returns 201', async () => {
    const mockIntent = {
      memo: 'abc-123',
      receivingAccount: 'snapie',
      amount: '3.000 HIVE',
      amountUsd: 1.2,
      expiresAt: new Date().toISOString()
    }
    payment.createHiveIntent.mockResolvedValue(mockIntent)

    const res = await request(app).post('/api/payment/hive-intent')
    expect(res.status).toBe(201)
    expect(res.body.memo).toBe('abc-123')
    expect(res.body.receivingAccount).toBe('snapie')
    expect(payment.createHiveIntent).toHaveBeenCalledWith('user123')
  })
})

describe('POST /api/payment/lightning-intent', () => {
  it('creates a Lightning intent and returns 201 with invoice', async () => {
    const mockIntent = {
      memo: 'ln-abc',
      invoice: 'lnbc1234...',
      amountUsd: 1.2,
      expiresAt: new Date().toISOString()
    }
    payment.createLightningIntent.mockResolvedValue(mockIntent)

    const res = await request(app).post('/api/payment/lightning-intent')
    expect(res.status).toBe(201)
    expect(res.body.invoice).toBe('lnbc1234...')
    expect(payment.createLightningIntent).toHaveBeenCalledWith('user123')
  })

  it('returns 500 when v4v.app call fails', async () => {
    payment.createLightningIntent.mockRejectedValue(new Error('v4v.app error 503'))
    const res = await request(app).post('/api/payment/lightning-intent')
    expect(res.status).toBe(500)
  })
})

describe('GET /api/payment/intent/:memo', () => {
  it('returns pending intent status', async () => {
    payment.getIntent.mockResolvedValue({
      _id: 'abc-123',
      type: 'hive',
      status: 'pending',
      txId: null,
      amountHive: '3.000 HIVE',
      amountUsd: 1.2,
      expiresAt: new Date()
    })

    const res = await request(app).get('/api/payment/intent/abc-123')
    expect(res.status).toBe(200)
    expect(res.body.status).toBe('pending')
    expect(res.body.txId).toBeNull()
  })

  it('returns confirmed intent with txId', async () => {
    payment.getIntent.mockResolvedValue({
      _id: 'abc-123',
      type: 'hive',
      status: 'confirmed',
      txId: 'hive-tx-abc',
      amountHive: '3.000 HIVE',
      amountUsd: 1.2,
      expiresAt: new Date()
    })

    const res = await request(app).get('/api/payment/intent/abc-123')
    expect(res.status).toBe(200)
    expect(res.body.status).toBe('confirmed')
    expect(res.body.txId).toBe('hive-tx-abc')
  })

  it('returns 404 for unknown memo', async () => {
    payment.getIntent.mockResolvedValue(null)
    const res = await request(app).get('/api/payment/intent/nonexistent')
    expect(res.status).toBe(404)
    expect(res.body.error).toBe('not_found')
  })
})
