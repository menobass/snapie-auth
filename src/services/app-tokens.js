import fs from 'fs'
import path from 'path'
import crypto from 'crypto'
import jwt from 'jsonwebtoken'
import { fileURLToPath } from 'url'

// App tokens are signed with their OWN keypair, never the session key: a token handed to a
// third party must not be replayable as a Snapie session cookie.

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const KEYS = path.join(__dirname, '..', '..', 'keys')
const TTL_SECONDS = 120

let loaded
function keys() {
  if (loaded !== undefined) return loaded
  try {
    const privatePem = fs.readFileSync(process.env.APP_JWT_PRIVATE_KEY_PATH || path.join(KEYS, 'app-private.pem'), 'utf8')
    const publicPem = fs.readFileSync(process.env.APP_JWT_PUBLIC_KEY_PATH || path.join(KEYS, 'app-public.pem'), 'utf8')
    const jwk = crypto.createPublicKey(publicPem).export({ format: 'jwk' })
    const kid = process.env.APP_JWT_KEY_ID || 'snapie-app-2026-01'
    loaded = { privatePem, jwk: { ...jwk, kid, alg: 'RS256', use: 'sig' }, kid }
  } catch {
    loaded = null // feature stays off until the keypair exists
  }
  return loaded
}

export const issuer = () => process.env.APP_JWT_ISSUER || 'https://auth.snapie.io'
export const isConfigured = () => keys() !== null
export const jwks = () => ({ keys: keys() ? [keys().jwk] : [] })

// Short-lived, single-purpose: proves "Snapie authenticated this user for <client>, answering <state>".
export function mintAppToken({ client, user, state }) {
  const k = keys()
  if (!k) throw new Error('app_login_not_configured')
  return jwt.sign(
    { name: user.name || null, hive_user: user.hiveUsername || null, nonce: state },
    k.privatePem,
    {
      algorithm: 'RS256', keyid: k.kid, issuer: issuer(), audience: client.id,
      subject: user._id.toString(), expiresIn: TTL_SECONDS, jwtid: crypto.randomUUID()
    }
  )
}

// test hook
export function _reset() { loaded = undefined }
