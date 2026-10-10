import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest'
import crypto from 'crypto'
import fs from 'fs'
import os from 'os'
import path from 'path'
import jwt from 'jsonwebtoken'
import { loadClients, getClient, isAllowedRedirect, isValidState } from '../../src/services/app-login.js'
import { mintAppToken, jwks, isConfigured, _reset } from '../../src/services/app-tokens.js'

const RAW = JSON.stringify({
  iot: { name: 'Hive IoT', redirects: ['https://iot.menosoft.xyz/auth/callback', 'menoiot://auth'] },
  bad: { name: 'No redirects', redirects: [] },
  'bad id!': { redirects: ['https://x.example/cb'] },
  unsafe: { redirects: ['http://x.example/cb', 'javascript:alert(1)', 'https://a:b@x.example/cb', 'https://x.example/cb#frag'] }
})

describe('app-login client registry', () => {
  const clients = loadClients(RAW)

  it('keeps only valid clients and redirects', () => {
    expect(Object.keys(clients)).toEqual(['iot'])
    expect(loadClients('not json')).toEqual({})
    expect(loadClients(undefined)).toEqual({})
  })

  it('looks up own properties only', () => {
    expect(getClient('iot', clients)?.name).toBe('Hive IoT')
    expect(getClient('__proto__', clients)).toBeNull()
    expect(getClient('constructor', clients)).toBeNull()
    expect(getClient(undefined, clients)).toBeNull()
  })

  it('matches redirects on scheme+host+path, query allowed', () => {
    const c = clients.iot
    expect(isAllowedRedirect(c, 'https://iot.menosoft.xyz/auth/callback')).toBe(true)
    expect(isAllowedRedirect(c, 'https://iot.menosoft.xyz/auth/callback?x=1')).toBe(true)
    expect(isAllowedRedirect(c, 'menoiot://auth')).toBe(true)
    expect(isAllowedRedirect(c, 'https://iot.menosoft.xyz/other')).toBe(false)
    expect(isAllowedRedirect(c, 'https://iot.menosoft.xyz.evil.com/auth/callback')).toBe(false)
    expect(isAllowedRedirect(c, 'http://iot.menosoft.xyz/auth/callback')).toBe(false)
    expect(isAllowedRedirect(c, 'https://iot.menosoft.xyz/auth/callback#x')).toBe(false)
    expect(isAllowedRedirect(c, 'javascript:alert(1)')).toBe(false)
    expect(isAllowedRedirect(c, undefined)).toBe(false)
  })

  it('validates state', () => {
    expect(isValidState('a'.repeat(16))).toBe(true)
    expect(isValidState('short')).toBe(false)
    expect(isValidState('a'.repeat(16) + '!')).toBe(false)
  })
})

describe('app tokens', () => {
  let dir
  beforeAll(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'app-keys-'))
    const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 })
    fs.writeFileSync(path.join(dir, 'priv.pem'), privateKey.export({ type: 'pkcs8', format: 'pem' }))
    fs.writeFileSync(path.join(dir, 'pub.pem'), publicKey.export({ type: 'spki', format: 'pem' }))
  })
  afterAll(() => fs.rmSync(dir, { recursive: true, force: true }))
  beforeEach(() => {
    process.env.APP_JWT_PRIVATE_KEY_PATH = path.join(dir, 'priv.pem')
    process.env.APP_JWT_PUBLIC_KEY_PATH = path.join(dir, 'pub.pem')
    process.env.APP_JWT_KEY_ID = 'test-kid'
    _reset()
  })

  it('is disabled without a keypair', () => {
    process.env.APP_JWT_PRIVATE_KEY_PATH = path.join(dir, 'missing.pem')
    _reset()
    expect(isConfigured()).toBe(false)
    expect(jwks()).toEqual({ keys: [] })
  })

  it('mints a token verifiable with the published JWKS', () => {
    const user = { _id: { toString: () => '64b7f0000000000000000001' }, name: 'Alice', hiveUsername: null }
    const state = 'n'.repeat(24)
    const token = mintAppToken({ client: { id: 'iot' }, user, state })

    const [jwk] = jwks().keys
    expect(jwk).toMatchObject({ kty: 'RSA', alg: 'RS256', kid: 'test-kid' })
    expect(jwk.d).toBeUndefined() // public half only

    const pub = crypto.createPublicKey({ key: jwk, format: 'jwk' })
    const claims = jwt.verify(token, pub, { algorithms: ['RS256'], audience: 'iot', issuer: 'https://auth.snapie.io' })
    expect(claims).toMatchObject({ sub: '64b7f0000000000000000001', name: 'Alice', hive_user: null, nonce: state })
    expect(claims.exp - claims.iat).toBe(120)
    expect(() => jwt.verify(token, pub, { algorithms: ['RS256'], audience: 'other' })).toThrow()
  })
})
