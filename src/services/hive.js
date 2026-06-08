import { Client, PrivateKey, Signature, PublicKey, cryptoUtils } from '@hiveio/dhive'

const rawNodes = process.env.HIVE_NODES || 'https://api.hive.blog,https://api.deathwing.me,https://api.openhive.network'
const NODES = rawNodes.split(',').map(n => n.trim()).filter(Boolean)

const TESTNET_NODES = ['https://testnet.openhive.network']
const network = process.env.HIVE_NETWORK || 'mainnet'
const nodes = network === 'testnet' ? TESTNET_NODES : NODES

export const client = new Client(nodes, { timeout: 4000, failoverThreshold: 4 })
export const bclient = new Client(nodes, { timeout: 3000, failoverThreshold: 2 })

export async function getAccount(username) {
  const [account] = await client.database.getAccounts([username])
  return account || null
}

export function verifySignature(username, message, signature, publicKey) {
  try {
    const msgHash = cryptoUtils.sha256(message)
    const sig = Signature.fromString(signature)
    const key = PublicKey.fromString(publicKey)
    return key.verify(msgHash, sig)
  } catch {
    return false
  }
}

export async function verifyHiveIdentity(username, message, signature) {
  const account = await getAccount(username)
  if (!account) return false
  const postingKeys = account.posting.key_auths.map(([key]) => key)
  const activeKeys = account.active.key_auths.map(([key]) => key)
  for (const pubKey of [...postingKeys, ...activeKeys]) {
    if (verifySignature(username, message, signature, pubKey)) return true
  }
  return false
}

export async function hasPostingAuthority(username, appAccount) {
  const account = await getAccount(username)
  if (!account) return false
  return account.posting.account_auths.some(([acc]) => acc === appAccount)
}

export function signMessage(message, wif) {
  const key = PrivateKey.fromString(wif)
  const hash = cryptoUtils.sha256(message)
  return key.sign(hash).toString()
}

export async function broadcastOps(operations, wif) {
  const key = PrivateKey.fromString(wif)
  return bclient.broadcast.sendOperations(operations, key)
}

export function isValidHivePubKey(keyStr) {
  try {
    PublicKey.fromString(keyStr)
    return true
  } catch {
    return false
  }
}

export function hiveErr(err) {
  if (!err) return 'unknown_error'
  if (typeof err.message === 'string') {
    // dhive wraps the JSON error — extract it
    const m = err.message.match(/"message":"([^"]+)"/)
    if (m) return m[1]
    return err.message.slice(0, 200)
  }
  return String(err)
}

export function isRcError(err) {
  const msg = (err?.message || '') + (err?.data?.message || '')
  return /insufficient.{0,20}resource.{0,20}credit/i.test(msg) ||
         /rc_exception/i.test(msg) ||
         /rc_plugin/i.test(msg)
}

export { PrivateKey }
