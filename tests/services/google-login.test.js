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

const CLIENT_ID = '1234-abc.apps.googleusercontent.com'
const STATE = 'abcdefghijklmnopqrstuvwx'
const nonceOf = (s) => crypto.createHash('sha256').update(s).digest('hex')

let verifyGoogleIdToken, router, resetGoogle, resetTokens, tokenPublicPem
beforeAll(async () => {
  process.env.APP_LOGIN_CLIENTS = JSON.stringify({
    myapp: { name: 'My App', redirects: ['myapp://auth'], google: [CLIENT_ID], apple: ['com.example.myapp'] },
    nogoogle: { name: 'No Google', redirects: ['nogoogle://auth'] },
    junk: { redirects: ['junk://auth'], google: ['bad id with spaces', 42] }
  })
  const kp = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 })
  const fs = await import('fs'), os = await import('os'), path = await import('path')
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'app-keys-'))
  fs.writeFileSync(path.join(dir, 'priv.pem'), kp.privateKey.export({ type: 'pkcs8', format: 'pem' }))
  fs.writeFileSync(path.join(dir, 'pub.pem'), kp.publicKey.export({ type: 'spki', format: 'pem' }))
  process.env.APP_JWT_PRIVATE_KEY_PATH = path.join(dir, 'priv.pem')
  process.env.APP_JWT_PUBLIC_KEY_PATH = path.join(dir, 'pub.pem')
  tokenPublicPem = kp.publicKey.export({ type: 'spki', format: 'pem' })
  ;({ verifyGoogleIdToken, _reset: resetGoogle } = await import('../../src/services/google.js'))
  ;({ _reset: resetTokens } = await import('../../src/services/app-tokens.js'))
  resetTokens()
  router = (await import('../../src/routes/app-login.js')).default
})

const googleToken = (claims = {}, { key = privateKey, kid = 'g1', aud = CLIENT_ID, iss = 'https://accounts.google.com', expiresIn = '5m' } = {}) =>
  jwt.sign({ sub: 'google-sub-1', nonce: nonceOf(STATE), email: 'a@example.com', email_verified: true,
    name: 'Ada Lovelace', picture: 'https://lh3.example/a.png', ...claims }, key,
  { algorithm: 'RS256', keyid: kid, issuer: iss, audience: aud, expiresIn })

let fetchMock
beforeEach(() => {
  resetGoogle()
  upsertUser.mockReset().mockImplementation(async (u) => ({ _id: 'u1', name: u.name, disabled: false }))
  fetchMock = vi.fn(async () => ({ ok: true, json: async () => ({ keys: [jwkOf(publicKey, 'g1')] }) }))
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => vi.unstubAllGlobals())

describe('verifyGoogleIdToken', () => {
  it('accepts a valid token, with either Google issuer spelling', async () => {
    expect((await verifyGoogleIdToken(googleToken(), [CLIENT_ID])).sub).toBe('google-sub-1')
    expect((await verifyGoogleIdToken(googleToken({}, { iss: 'accounts.google.com' }), [CLIENT_ID])).sub).toBe('google-sub-1')
  })
  it('rejects wrong audience, issuer, signature, expiry and missing audiences', async () => {
    expect(await verifyGoogleIdToken(googleToken({}, { aud: 'other.apps.googleusercontent.com' }), [CLIENT_ID])).toBeNull()
    expect(await verifyGoogleIdToken(googleToken({}, { iss: 'https://evil.example' }), [CLIENT_ID])).toBeNull()
    expect(await verifyGoogleIdToken(googleToken({}, { key: other.privateKey }), [CLIENT_ID])).toBeNull()
    expect(await verifyGoogleIdToken(googleToken({}, { expiresIn: -10 }), [CLIENT_ID])).toBeNull()
    expect(await verifyGoogleIdToken(googleToken(), [])).toBeNull()
    expect(await verifyGoogleIdToken('garbage', [CLIENT_ID])).toBeNull()
  })
})

describe('POST /api/app-login/google', () => {
  const post = (body) => request(express().use(express.json()).use('/api/app-login', router))
    .post('/api/app-login/google').send(body)

  it('returns an app token bound to client, user and state', async () => {
    const res = await post({ client: 'myapp', idToken: googleToken(), state: STATE })
    expect(res.status).toBe(200)
    const claims = jwt.verify(res.body.token, tokenPublicPem, { algorithms: ['RS256'], audience: 'myapp' })
    expect(claims.sub).toBe('u1')
    expect(claims.nonce).toBe(STATE)
    expect(claims.name).toBe('Ada Lovelace')
    // same provider/providerId as the web Google login, so it's the same Snapie user
    expect(upsertUser).toHaveBeenCalledWith(expect.objectContaining({
      provider: 'google', providerId: 'google-sub-1', emailHash: 'hash(a@example.com)', name: 'Ada Lovelace' }))
  })

  it('does not hash an unverified email', async () => {
    await post({ client: 'myapp', idToken: googleToken({ email_verified: false }), state: STATE })
    expect(upsertUser).toHaveBeenCalledWith(expect.objectContaining({ emailHash: null }))
  })

  it('rejects an ID token made for a different login attempt (nonce)', async () => {
    const res = await post({ client: 'myapp', idToken: googleToken({ nonce: nonceOf('another-state-another-state') }), state: STATE })
    expect(res.status).toBe(401)
    expect(upsertUser).not.toHaveBeenCalled()
    expect((await post({ client: 'myapp', idToken: googleToken({ nonce: undefined }), state: STATE })).status).toBe(401)
  })

  it('rejects a token for another OAuth client id', async () => {
    const res = await post({ client: 'myapp', idToken: googleToken({}, { aud: 'other.apps.googleusercontent.com' }), state: STATE })
    expect(res.status).toBe(401)
  })

  it('refuses unknown clients, clients without google (or with only invalid ids), and bad input', async () => {
    expect((await post({ client: 'nope', idToken: googleToken(), state: STATE })).body.error).toBe('invalid_client')
    expect((await post({ client: 'nogoogle', idToken: googleToken(), state: STATE })).body.error).toBe('google_not_enabled')
    expect((await post({ client: 'junk', idToken: googleToken(), state: STATE })).body.error).toBe('google_not_enabled')
    expect((await post({ client: 'myapp', idToken: googleToken(), state: 'short' })).body.error).toBe('invalid_state')
    expect((await post({ client: 'myapp', state: STATE })).status).toBe(400)
  })

  it('blocks disabled accounts', async () => {
    upsertUser.mockResolvedValue({ _id: 'u1', name: null, disabled: true })
    expect((await post({ client: 'myapp', idToken: googleToken(), state: STATE })).status).toBe(403)
  })
})
