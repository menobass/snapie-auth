import crypto from 'crypto'
import { PrivateKey } from '@hiveio/dhive'

const PEPPER = () => process.env.KEY_ENCRYPTION_PEPPER || ''

// Derive AES key deterministically from userId + pepper.
// This is the sole key for all custodial accounts — no user secret needed.
export function deriveServerKey(userId) {
  return crypto.createHmac('sha256', PEPPER()).update(userId).digest('hex')
}

export function encryptKey(plaintext, keyHex) {
  const key = Buffer.from(keyHex, 'hex')
  const iv = crypto.randomBytes(12)
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv)
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()])
  const authTag = cipher.getAuthTag()
  return {
    iv: iv.toString('hex'),
    // ciphertext = encrypted bytes + 16-byte auth tag (mirrors decryptKey)
    ciphertext: Buffer.concat([encrypted, authTag]).toString('hex')
  }
}

export function decryptKey(encryptedKey, keyHex) {
  const key = Buffer.from(keyHex, 'hex')
  const iv = Buffer.from(encryptedKey.iv, 'hex')
  const raw = Buffer.from(encryptedKey.ciphertext, 'hex')
  const authTag = raw.slice(-16)
  const data = raw.slice(0, -16)
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv)
  decipher.setAuthTag(authTag)
  return decipher.update(data, null, 'utf8') + decipher.final('utf8')
}

// Generate a Hive master password, then derive all 4 role keypairs from it
// via PrivateKey.fromLogin — the same derivation Hive wallets (Keychain, PeakD)
// use, so the master password alone can regenerate every key.
// The 'P' prefix matches the conventional Hive master-password format.
export function generateMasterPassword() {
  return 'P' + PrivateKey.fromSeed(crypto.randomBytes(32).toString('hex')).toString()
}

// Generate 4 Hive keypairs server-side for custodial accounts, all derived
// from a single master password. The master password is encrypted and stored
// alongside the keys so it can be handed back to the user on export.
// Returns { ownerPub, activePub, postingPub, memoPub, encryptedKeys, encryptedMasterPassword }
export function generateAndEncryptKeys(userId, username) {
  const roles = ['owner', 'active', 'posting', 'memo']
  const serverKey = deriveServerKey(userId)
  const masterPassword = generateMasterPassword()
  const pubKeys = {}
  const encryptedKeys = {}

  for (const role of roles) {
    const priv = PrivateKey.fromLogin(username, masterPassword, role)
    pubKeys[`${role}Pub`] = priv.createPublic().toString()
    encryptedKeys[role] = encryptKey(priv.toString(), serverKey)
  }

  return {
    ...pubKeys,
    encryptedKeys,
    encryptedMasterPassword: encryptKey(masterPassword, serverKey)
  }
}

// Verify decrypted WIF keys match what's on-chain
export function verifyDecryptedKeys(decryptedKeys, onChainAccount) {
  try {
    const roles = ['owner', 'active', 'posting', 'memo']
    for (const role of roles) {
      const wif = decryptedKeys[role]
      if (!wif) return false
      const pub = PrivateKey.fromString(wif).createPublic().toString()
      if (role === 'memo') {
        if (onChainAccount.memo_key !== pub) return false
      } else {
        const keyAuths = onChainAccount[role]?.key_auths || []
        if (!keyAuths.some(([k]) => k === pub)) return false
      }
    }
    return true
  } catch {
    return false
  }
}
