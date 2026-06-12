import { describe, it, expect, vi, beforeEach } from 'vitest'

// --- mocks must be declared before dynamic imports ---

const mockInsertOne = vi.fn().mockResolvedValue({})
const mockFind = vi.fn()
const mockUpdateOne = vi.fn().mockResolvedValue({ modifiedCount: 1 })
const mockFindOne = vi.fn()
const mockCountDocuments = vi.fn().mockResolvedValue(0)  // default: no pending intents

vi.mock('../../src/services/db.js', () => ({
  paymentIntents: () => ({
    insertOne: mockInsertOne,
    find: mockFind,
    updateOne: mockUpdateOne,
    findOne: mockFindOne,
    countDocuments: mockCountDocuments
  }),
  users: () => ({ updateOne: mockUpdateOne })
}))

vi.mock('../../src/services/hive.js', () => ({
  getAccountCreationFee: vi.fn().mockResolvedValue('3.000 HIVE'),
  client: { database: { call: vi.fn() } }
}))

vi.mock('../../src/services/account-value.js', () => ({
  getHivePrice: vi.fn().mockResolvedValue(0.4)
}))

global.fetch = vi.fn()

const { createHiveIntent, createLightningIntent, getIntent, pollPendingIntents } =
  await import('../../src/services/payment.js')
const hive = await import('../../src/services/hive.js')
const mockHistoryCall = hive.client.database.call

beforeEach(() => {
  vi.clearAllMocks()
  mockFind.mockReturnValue({ toArray: vi.fn().mockResolvedValue([]) })
  mockCountDocuments.mockResolvedValue(0)
  process.env.SNAPIE_RECEIVING_ACCOUNT = 'snapie-test'
  process.env.SNAPIE_LIGHTNING_HIVE_ACCOUNT = 'snapie-test'
})

describe('createHiveIntent', () => {
  it('inserts a pending intent with correct fields', async () => {
    await createHiveIntent('user123')
    expect(mockInsertOne).toHaveBeenCalledOnce()
    const doc = mockInsertOne.mock.calls[0][0]
    expect(doc.type).toBe('hive')
    expect(doc.purpose).toBe('account_creation')
    expect(doc.amountHive).toBe('3.000 HIVE')
    expect(doc.amountUsd).toBe(1.2)
    expect(doc.status).toBe('pending')
    expect(doc.lightningInvoice).toBeNull()
    expect(typeof doc._id).toBe('string')
  })

  it('returns memo, receivingAccount, amount, and expiresAt', async () => {
    const result = await createHiveIntent('user123')
    expect(result.memo).toBeDefined()
    expect(result.receivingAccount).toBe('snapie-test')
    expect(result.amount).toBe('3.000 HIVE')
    expect(result.expiresAt).toBeInstanceOf(Date)
  })

  it('generates a unique memo on each call', async () => {
    const r1 = await createHiveIntent('user123')
    const r2 = await createHiveIntent('user123')
    expect(r1.memo).not.toBe(r2.memo)
  })

  it('throws too_many_pending_intents when cap is reached', async () => {
    mockCountDocuments.mockResolvedValue(3)
    await expect(createHiveIntent('user123')).rejects.toThrow('too_many_pending_intents')
  })
})

describe('createLightningIntent', () => {
  it('calls v4v.app with correct params and returns BOLT11 invoice', async () => {
    global.fetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ payment_request: 'lnbc1234...' })
    })

    const result = await createLightningIntent('user456')

    expect(global.fetch).toHaveBeenCalledWith(
      'https://api.v4v.app/v1/new_invoice_hive',
      expect.objectContaining({ method: 'POST' })
    )
    const body = JSON.parse(global.fetch.mock.calls[0][1].body)
    expect(body.currency).toBe('USD')
    expect(body.app_name).toBe('snapie')
    expect(typeof body.message).toBe('string')

    expect(result.invoice).toBe('lnbc1234...')
    expect(result.memo).toBeDefined()
    expect(result.expiresAt).toBeInstanceOf(Date)
  })

  it('throws when v4v.app returns an error status', async () => {
    global.fetch.mockResolvedValueOnce({
      ok: false,
      status: 503,
      text: async () => 'service unavailable'
    })
    await expect(createLightningIntent('user456')).rejects.toThrow('v4v.app error 503')
  })

  it('throws when v4v.app response has no payment_request', async () => {
    global.fetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ error: 'bad account' })
    })
    await expect(createLightningIntent('user456')).rejects.toThrow('no payment_request')
  })

  it('throws too_many_pending_intents when cap is reached', async () => {
    mockCountDocuments.mockResolvedValue(3)
    await expect(createLightningIntent('user456')).rejects.toThrow('too_many_pending_intents')
  })
})

describe('pollPendingIntents', () => {
  const makeTransfer = (from, to, memo, amount = '3.000 HIVE') => [
    0,
    {
      trx_id: 'abc123',
      op: ['transfer', { from, to, amount, memo }]
    }
  ]

  const baseIntent = {
    _id: 'test-memo-uuid',
    userId: '507f1f77bcf86cd799439011',
    type: 'hive',
    purpose: 'account_creation',
    status: 'pending',
    amountHive: '3.000 HIVE'
  }

  it('confirms a matching HIVE intent with correct amount', async () => {
    mockFind.mockReturnValue({ toArray: vi.fn().mockResolvedValue([baseIntent]) })
    mockHistoryCall.mockResolvedValue([
      makeTransfer('someuser', 'snapie-test', 'test-memo-uuid', '3.000 HIVE')
    ])

    await pollPendingIntents()

    expect(mockUpdateOne).toHaveBeenCalledWith(
      { _id: 'test-memo-uuid', status: 'pending' },
      expect.objectContaining({ $set: expect.objectContaining({ status: 'confirmed', txId: 'abc123' }) })
    )
  })

  it('accepts payment within 5% tolerance (Lightning slippage)', async () => {
    mockFind.mockReturnValue({ toArray: vi.fn().mockResolvedValue([baseIntent]) })
    // 2.91 HIVE = 97% of 3.000 — within the 5% tolerance
    mockHistoryCall.mockResolvedValue([
      makeTransfer('v4vapp', 'snapie-test', 'test-memo-uuid', '2.910 HIVE')
    ])
    const intent = { ...baseIntent, type: 'lightning' }
    mockFind.mockReturnValue({ toArray: vi.fn().mockResolvedValue([intent]) })

    await pollPendingIntents()

    expect(mockUpdateOne).toHaveBeenCalled()
  })

  it('rejects underpayment below 5% tolerance', async () => {
    mockFind.mockReturnValue({ toArray: vi.fn().mockResolvedValue([baseIntent]) })
    // 2.80 HIVE = ~93% of 3.000 — outside tolerance
    mockHistoryCall.mockResolvedValue([
      makeTransfer('someuser', 'snapie-test', 'test-memo-uuid', '2.800 HIVE')
    ])

    await pollPendingIntents()

    expect(mockUpdateOne).not.toHaveBeenCalled()
  })

  it('confirms a Lightning intent only when sender is v4vapp', async () => {
    const intent = { ...baseIntent, _id: 'ln-memo-uuid', type: 'lightning' }
    mockFind.mockReturnValue({ toArray: vi.fn().mockResolvedValue([intent]) })
    mockHistoryCall.mockResolvedValue([
      makeTransfer('v4vapp', 'snapie-test', 'ln-memo-uuid')
    ])

    await pollPendingIntents()

    expect(mockUpdateOne).toHaveBeenCalled()
  })

  it('does NOT confirm a Lightning intent when sender is not v4vapp', async () => {
    const intent = { ...baseIntent, _id: 'ln-memo-uuid', type: 'lightning' }
    mockFind.mockReturnValue({ toArray: vi.fn().mockResolvedValue([intent]) })
    mockHistoryCall.mockResolvedValue([
      makeTransfer('somerandomperson', 'snapie-test', 'ln-memo-uuid')
    ])

    await pollPendingIntents()

    expect(mockUpdateOne).not.toHaveBeenCalled()
  })

  it('does not confirm when memo does not match any intent', async () => {
    mockFind.mockReturnValue({ toArray: vi.fn().mockResolvedValue([baseIntent]) })
    mockHistoryCall.mockResolvedValue([
      makeTransfer('someuser', 'snapie-test', 'completely-different-memo')
    ])

    await pollPendingIntents()

    expect(mockUpdateOne).not.toHaveBeenCalled()
  })

  it('skips non-transfer operations', async () => {
    mockFind.mockReturnValue({ toArray: vi.fn().mockResolvedValue([baseIntent]) })
    mockHistoryCall.mockResolvedValue([
      [0, { trx_id: 'xyz', op: ['vote', { voter: 'a', author: 'b', permlink: 'c', weight: 1 }] }]
    ])

    await pollPendingIntents()
    expect(mockUpdateOne).not.toHaveBeenCalled()
  })

  it('does nothing when there are no pending intents', async () => {
    mockFind.mockReturnValue({ toArray: vi.fn().mockResolvedValue([]) })
    await pollPendingIntents()
    expect(mockHistoryCall).not.toHaveBeenCalled()
  })
})
