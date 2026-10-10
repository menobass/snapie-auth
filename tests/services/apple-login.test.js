import { describe, it, expect, beforeAll, beforeEach, afterEach, vi } from 'vitest'
import crypto from 'crypto'
import jwt from 'jsonwebtoken'
import express from 'express'
import request from 'supertest'

const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 })
const other = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 })
const jwkOf = (k, kid) => ({ ...k.export({ format: 'jwk' }), kid, alg: 'RS256', use: 'sig' })

const upsertUser = vi.fn()
vi.mock('../../src/services/users.js', () => ({
  getUserById: vi.fn(),
  upsertUser: (...a) => upsertUser(...a),
  hashEmail: (e) => `hash(${e})`
}))
vi.mock('../../src/services/auth.js', () => ({ authMiddleware: (_q, _r, n) => n() }))
vi.mock('../../src/services/csrf.js', () => ({ csrfMiddleware: (_q, _r, n) => n() }))

const BUNDLE = 'com.example.myapp'
const STATE = 'abcdefghijklmnopqrstuvwx'
const nonceOf = (s) => crypto.createHash('sha256').update(s).digest('hex')

let verifyAppleIdentityToken, router, resetApple, resetTokens, tokenPublicPem
beforeAll(async () => {
  process.env.APP_LOGIN_CLIENTS = JSON.stringify({
    myapp: { name: 'My App', redirects: ['myapp://auth'], apple: [BUNDLE] },
    noapple: { name: 'No Apple', redirects: ['noapple://auth'] }
  })
  const kp = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 })
  const fs = await import('fs'), os = await import('os'), path = await import('path')
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'app-keys-'))
  fs.writeFileSync(path.join(dir, 'priv.pem'), kp.privateKey.export({ type: 'pkcs8', format: 'pem' }))
  fs.writeFileSync(path.join(dir, 'pub.pem'), kp.publicKey.export({ type: 'spki', format: 'pem' }))
  process.env.APP_JWT_PRIVATE_KEY_PATH = path.join(dir, 'priv.pem')
  process.env.APP_JWT_PUBLIC_KEY_PATH = path.join(dir, 'pub.pem')
  tokenPublicPem = kp.publicKey.export({ type: 'spki', format: 'pem' })
  ;({ verifyAppleIdentityToken, _reset: resetApple } = await import('../../src/services/apple.js'))
  ;({ _reset: resetTokens } = await import('../../src/services/app-tokens.js'))
  resetTokens()
  router = (await import('../../src/routes/app-login.js')).default
})

const appleToken = (claims = {}, { key = privateKey, kid = 'k1', aud = BUNDLE, iss = 'https://appleid.apple.com', expiresIn = '5m' } = {}) =>
  jwt.sign({ sub: 'apple-user-1', nonce: nonceOf(STATE), email: 'p@privaterelay.appleid.com', ...claims }, key,
    { algorithm: 'RS256', keyid: kid, issuer: iss, audience: aud, expiresIn })

let fetchMock
beforeEach(() => {
  resetApple()
  upsertUser.mockReset().mockImplementation(async (u) => ({ _id: 'u1', name: u.name, disabled: false }))
  fetchMock = vi.fn(async () => ({ ok: true, json: async () => ({ keys: [jwkOf(publicKey, 'k1')] }) }))
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => vi.unstubAllGlobals())

describe('verifyAppleIdentityToken', () => {
  it('accepts a valid token for an allowed audience', async () => {
    const p = await verifyAppleIdentityToken(appleToken(), [BUNDLE])
    expect(p.sub).toBe('apple-user-1')
  })
  it('rejects wrong audience, issuer, signature, expiry and missing audiences', async () => {
    expect(await verifyAppleIdentityToken(appleToken({}, { aud: 'com.other.app' }), [BUNDLE])).toBeNull()
    expect(await verifyAppleIdentityToken(appleToken({}, { iss: 'https://evil.example' }), [BUNDLE])).toBeNull()
    expect(await verifyAppleIdentityToken(appleToken({}, { key: other.privateKey }), [BUNDLE])).toBeNull()
    expect(await verifyAppleIdentityToken(appleToken({}, { expiresIn: -10 }), [BUNDLE])).toBeNull()
    expect(await verifyAppleIdentityToken(appleToken(), [])).toBeNull()
    expect(await verifyAppleIdentityToken('garbage', [BUNDLE])).toBeNull()
  })
  it('refetches keys once when the kid is unknown (rotation)', async () => {
    fetchMock.mockResolvedValueOnce({ ok: true, json: async () => ({ keys: [jwkOf(other.publicKey, 'old')] }) })
    const p = await verifyAppleIdentityToken(appleToken(), [BUNDLE])
    expect(p.sub).toBe('apple-user-1')
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })
})

describe('POST /api/app-login/apple', () => {
  // router is imported in beforeAll, so the app is built per request
  const post = (body) => request(express().use(express.json()).use('/api/app-login', router))
    .post('/api/app-login/apple').send(body)

  it('returns an app token bound to client, user and state', async () => {
    const res = await post({ client: 'myapp', identityToken: appleToken(), state: STATE, name: { firstName: 'Ada', lastName: 'L' } })
    expect(res.status).toBe(200)
    const claims = jwt.verify(res.body.token, tokenPublicPem, { algorithms: ['RS256'], audience: 'myapp' })
    expect(claims.sub).toBe('u1')
    expect(claims.nonce).toBe(STATE)
    expect(claims.name).toBe('Ada L')
    expect(upsertUser).toHaveBeenCalledWith(expect.objectContaining({
      provider: 'apple', providerId: 'apple-user-1', emailHash: 'hash(p@privaterelay.appleid.com)', name: 'Ada L' }))
  })

  it('rejects an identity token made for a different login attempt (nonce)', async () => {
    const res = await post({ client: 'myapp', identityToken: appleToken({ nonce: nonceOf('another-state-another-state') }), state: STATE })
    expect(res.status).toBe(401)
    expect(upsertUser).not.toHaveBeenCalled()
    expect((await post({ client: 'myapp', identityToken: appleToken({ nonce: undefined }), state: STATE })).status).toBe(401)
  })

  it('rejects a token for another app bundle id', async () => {
    const res = await post({ client: 'myapp', identityToken: appleToken({}, { aud: 'com.other.app' }), state: STATE })
    expect(res.status).toBe(401)
  })

  it('refuses unknown clients, clients without apple, and bad state', async () => {
    expect((await post({ client: 'nope', identityToken: appleToken(), state: STATE })).body.error).toBe('invalid_client')
    expect((await post({ client: 'noapple', identityToken: appleToken(), state: STATE })).body.error).toBe('apple_not_enabled')
    expect((await post({ client: 'myapp', identityToken: appleToken(), state: 'short' })).body.error).toBe('invalid_state')
    expect((await post({ client: 'myapp', state: STATE })).status).toBe(400)
  })

  it('blocks disabled accounts', async () => {
    upsertUser.mockResolvedValue({ _id: 'u1', name: null, disabled: true })
    const res = await post({ client: 'myapp', identityToken: appleToken(), state: STATE })
    expect(res.status).toBe(403)
  })
})
