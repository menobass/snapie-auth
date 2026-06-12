import assert from 'node:assert/strict'
import { PrivateKey } from '@hiveio/dhive'
import {
  generateMasterPassword,
  generateAndEncryptKeys,
  decryptKey,
  deriveServerKey
} from '../src/services/key-crypto.js'

process.env.KEY_ENCRYPTION_PEPPER = 'test-pepper-snapie-keygen-unit!!'

const USERNAME = 'testuser'
const USER_ID = '000000000000000000000001'
const ROLES = ['owner', 'active', 'posting', 'memo']

// generateMasterPassword: format
const mp = generateMasterPassword()
assert.ok(mp.startsWith('P'), 'master password must start with P')
assert.ok(mp.length >= 51, 'master password must be at least 51 chars (P + WIF)')

// generateAndEncryptKeys: return shape
const result = generateAndEncryptKeys(USER_ID, USERNAME)
assert.ok(result.encryptedMasterPassword, 'must return encryptedMasterPassword')
assert.ok(result.encryptedKeys, 'must return encryptedKeys')
for (const role of ROLES) {
  assert.ok(result[`${role}Pub`], `must return ${role}Pub`)
  assert.ok(result.encryptedKeys[role], `must return encryptedKeys.${role}`)
}

// round-trip: decrypt master password and re-derive all four public keys
const serverKey = deriveServerKey(USER_ID)
const decryptedMp = decryptKey(result.encryptedMasterPassword, serverKey)
assert.ok(decryptedMp.startsWith('P'), 'decrypted master password must start with P')

for (const role of ROLES) {
  const rederived = PrivateKey.fromLogin(USERNAME, decryptedMp, role)
  assert.equal(
    rederived.createPublic().toString(),
    result[`${role}Pub`],
    `${role} public key must match after re-deriving from master password`
  )
}

// round-trip: decrypt each individual key and verify against stored pub
for (const role of ROLES) {
  const wif = decryptKey(result.encryptedKeys[role], serverKey)
  const pub = PrivateKey.fromString(wif).createPublic().toString()
  assert.equal(pub, result[`${role}Pub`], `decrypted ${role} key must match stored pub`)
}

console.log('All keygen tests passed.')
