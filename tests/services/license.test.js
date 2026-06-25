import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'

const mockFindOne = vi.fn()
vi.mock('../../src/services/db.js', () => ({
  accountJobs: () => ({ findOne: mockFindOne })
}))

const mockGetAccount = vi.fn()
const mockBroadcastOps = vi.fn()
vi.mock('../../src/services/hive.js', () => ({
  getAccount: (...args) => mockGetAccount(...args),
  broadcastOps: (...args) => mockBroadcastOps(...args),
  hiveErr: err => err?.message || 'unknown_error',
  isRcError: () => false
}))

const mockCheckUsernameAvailability = vi.fn()
const mockCreateJob = vi.fn()
vi.mock('../../src/services/account-jobs.js', () => ({
  isValidHiveUsername: username =>
    typeof username === 'string' &&
    username.length >= 3 && username.length <= 16 &&
    /^[a-z0-9][a-z0-9\-.]*[a-z0-9]$/.test(username) &&
    !/--/.test(username),
  checkUsernameAvailability: (...args) => mockCheckUsernameAvailability(...args),
  createJob: (...args) => mockCreateJob(...args)
}))

const {
  isValidPluginId,
  isValidMachineId,
  slugifyUsernameBase,
  generateUsername,
  getOrCreateHiveAccountForLicense,
  broadcastLicenseActivation
} = await import('../../src/services/license.js')

beforeEach(() => {
  vi.clearAllMocks()
  process.env.SNAPIE_ACCOUNT = 'snapie'
  process.env.SNAPIE_POSTING_KEY = '5KtestPostingKey'
})

afterEach(() => {
  vi.useRealTimers()
})

describe('isValidPluginId', () => {
  it('accepts alphanumeric + underscore slugs', () => {
    expect(isValidPluginId('pechi_saturator')).toBe(true)
    expect(isValidPluginId('pechi_eq')).toBe(true)
  })
  it('rejects invalid input', () => {
    expect(isValidPluginId('')).toBe(false)
    expect(isValidPluginId('has space')).toBe(false)
    expect(isValidPluginId('has/slash')).toBe(false)
    expect(isValidPluginId(null)).toBe(false)
    expect(isValidPluginId('a'.repeat(65))).toBe(false)
  })
})

describe('isValidMachineId', () => {
  it('accepts 16 hex chars', () => {
    expect(isValidMachineId('a3f9b2c1d4e5f6a7')).toBe(true)
    expect(isValidMachineId('A3F9B2C1D4E5F6A7')).toBe(true)
  })
  it('rejects wrong length or non-hex', () => {
    expect(isValidMachineId('a3f9b2c1')).toBe(false)
    expect(isValidMachineId('zzzzzzzzzzzzzzzz')).toBe(false)
    expect(isValidMachineId(null)).toBe(false)
  })
})

describe('slugifyUsernameBase', () => {
  it('lowercases and strips disallowed characters', () => {
    expect(slugifyUsernameBase('Jose Mena')).toBe('jose-mena')
  })
  it('strips accents', () => {
    expect(slugifyUsernameBase('José')).toBe('jose')
  })
  it('falls back to "user" for empty or unusable input', () => {
    expect(slugifyUsernameBase('')).toBe('user')
    expect(slugifyUsernameBase(null)).toBe('user')
    expect(slugifyUsernameBase('123')).toBe('user')
    expect(slugifyUsernameBase('!!!')).toBe('user')
    expect(slugifyUsernameBase('王')).toBe('user')
  })
})

describe('generateUsername', () => {
  it('always produces a valid Hive username shape', () => {
    const inputs = ['Jose Mena', '', null, '123', '!!!', 'A Very Long Display Name Indeed', 'José']
    for (const input of inputs) {
      const username = generateUsername(input)
      expect(username.length).toBeGreaterThanOrEqual(3)
      expect(username.length).toBeLessThanOrEqual(16)
      expect(username).toMatch(/^[a-z][a-z0-9-]*[a-z0-9]$/)
    }
  })
})

describe('getOrCreateHiveAccountForLicense', () => {
  it('reuses an existing hiveUsername without touching account creation', async () => {
    const user = { _id: { toString: () => 'u1' }, hiveUsername: 'existing-user', name: 'Existing User' }
    const result = await getOrCreateHiveAccountForLicense(user)
    expect(result).toEqual({ username: 'existing-user' })
    expect(mockGetAccount).not.toHaveBeenCalled()
    expect(mockCreateJob).not.toHaveBeenCalled()
  })

  it('returns no_acts when Snapie has zero pending claimed accounts', async () => {
    mockGetAccount.mockResolvedValue({ pending_claimed_accounts: 0 })
    const user = { _id: { toString: () => 'u1' }, hiveUsername: null, name: 'New User' }
    const result = await getOrCreateHiveAccountForLicense(user)
    expect(result).toEqual({ error: 'no_acts' })
    expect(mockCreateJob).not.toHaveBeenCalled()
  })

  it('creates a job and returns the username once confirmed', async () => {
    mockGetAccount.mockResolvedValue({ pending_claimed_accounts: 5 })
    mockCheckUsernameAvailability.mockResolvedValue({ available: true })
    mockCreateJob.mockResolvedValue({ _id: 'job-1' })
    mockFindOne.mockResolvedValue({ status: 'confirmed', username: 'new-user-ab12cd' })

    const user = { _id: { toString: () => 'u1' }, hiveUsername: null, name: 'New User' }
    const result = await getOrCreateHiveAccountForLicense(user)

    expect(result).toEqual({ username: 'new-user-ab12cd' })
    expect(mockCreateJob).toHaveBeenCalledOnce()
    expect(mockCreateJob.mock.calls[0][0]).toMatchObject({ userId: 'u1', custodyMode: 'custodial' })
  })

  it('retries username generation on collision', async () => {
    mockGetAccount.mockResolvedValue({ pending_claimed_accounts: 5 })
    mockCheckUsernameAvailability
      .mockResolvedValueOnce({ available: false })
      .mockResolvedValueOnce({ available: true })
    mockCreateJob.mockResolvedValue({ _id: 'job-1' })
    mockFindOne.mockResolvedValue({ status: 'confirmed', username: 'retry-user' })

    const user = { _id: { toString: () => 'u1' }, hiveUsername: null, name: 'Retry User' }
    const result = await getOrCreateHiveAccountForLicense(user)

    expect(result).toEqual({ username: 'retry-user' })
    expect(mockCheckUsernameAvailability).toHaveBeenCalledTimes(2)
  })

  it('returns the job error when account creation fails', async () => {
    mockGetAccount.mockResolvedValue({ pending_claimed_accounts: 5 })
    mockCheckUsernameAvailability.mockResolvedValue({ available: true })
    mockCreateJob.mockResolvedValue({ _id: 'job-1' })
    mockFindOne.mockResolvedValue({ status: 'failed', lastError: 'insufficient_rc' })

    const user = { _id: { toString: () => 'u1' }, hiveUsername: null, name: 'Fail User' }
    const result = await getOrCreateHiveAccountForLicense(user)

    expect(result).toEqual({ error: 'insufficient_rc' })
  })

  it('times out if the job never reaches a terminal state', async () => {
    vi.useFakeTimers()
    mockGetAccount.mockResolvedValue({ pending_claimed_accounts: 5 })
    mockCheckUsernameAvailability.mockResolvedValue({ available: true })
    mockCreateJob.mockResolvedValue({ _id: 'job-1' })
    mockFindOne.mockResolvedValue({ status: 'pending' })

    const user = { _id: { toString: () => 'u1' }, hiveUsername: null, name: 'Slow User' }
    const promise = getOrCreateHiveAccountForLicense(user)
    await vi.advanceTimersByTimeAsync(30000)
    const result = await promise

    expect(result).toEqual({ error: 'timeout' })
  })
})

describe('broadcastLicenseActivation', () => {
  it('broadcasts a pechi_license custom_json with the expected shape', async () => {
    mockBroadcastOps.mockResolvedValue({ id: 'tx123' })
    const result = await broadcastLicenseActivation({
      hiveUsername: 'josemena-a1b2c3',
      plugin: 'pechi_saturator',
      machine: 'a3f9b2c1d4e5f6a7'
    })

    expect(result).toEqual({ txId: 'tx123' })
    expect(mockBroadcastOps).toHaveBeenCalledOnce()
    const [[op], wif] = mockBroadcastOps.mock.calls[0]
    expect(op[0]).toBe('custom_json')
    expect(op[1].required_posting_auths).toEqual(['josemena-a1b2c3'])
    expect(op[1].id).toBe('pechi_license')
    expect(JSON.parse(op[1].json)).toEqual({
      op: 'activate',
      plugin: 'pechi_saturator',
      machine_id: 'a3f9b2c1d4e5f6a7'
    })
    expect(wif).toBe('5KtestPostingKey')
  })

  it('returns a mapped error when broadcast fails', async () => {
    mockBroadcastOps.mockRejectedValue(new Error('boom'))
    const result = await broadcastLicenseActivation({
      hiveUsername: 'josemena-a1b2c3',
      plugin: 'pechi_saturator',
      machine: 'a3f9b2c1d4e5f6a7'
    })
    expect(result).toEqual({ error: 'boom' })
  })
})
