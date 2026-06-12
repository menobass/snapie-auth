import { describe, it, expect, vi, beforeEach } from 'vitest'

// vi.hoisted runs before vi.mock factories, letting us share the mock reference
const mockCall = vi.hoisted(() => vi.fn())

vi.mock('@hiveio/dhive', () => {
  function Client() {
    this.database = { call: mockCall }
    this.broadcast = {}
  }
  return {
    Client,
    PrivateKey: { fromString: vi.fn() },
    Signature: { fromString: vi.fn() },
    PublicKey: { fromString: vi.fn() },
    cryptoUtils: { sha256: vi.fn() }
  }
})

// Import after mock is in place
const { getAccountCreationFee, getChainProperties } = await import('../../src/services/hive.js')

beforeEach(() => {
  mockCall.mockReset()
})

describe('getAccountCreationFee', () => {
  it('returns account_creation_fee from chain properties', async () => {
    mockCall.mockResolvedValueOnce({ account_creation_fee: '3.000 HIVE' })
    const fee = await getAccountCreationFee()
    expect(fee).toBe('3.000 HIVE')
    expect(mockCall).toHaveBeenCalledWith('get_chain_properties', [])
  })

  it('parses the fee string correctly for different witness amounts', async () => {
    mockCall.mockResolvedValueOnce({ account_creation_fee: '5.000 HIVE' })
    const fee = await getAccountCreationFee()
    expect(fee).toMatch(/^\d+\.\d{3} HIVE$/)
    expect(parseFloat(fee)).toBeGreaterThan(0)
  })
})

describe('getChainProperties cache', () => {
  it('hits the chain only once within the TTL window', async () => {
    // Force cache miss by resetting the mock (cache may still hold prior value);
    // we verify call count over two sequential invocations.
    mockCall.mockResolvedValue({ account_creation_fee: '3.000 HIVE' })

    await getChainProperties()
    const callCount = mockCall.mock.calls.length
    await getChainProperties()

    // Second call must not have added another chain hit
    expect(mockCall.mock.calls.length).toBe(callCount)
  })
})
