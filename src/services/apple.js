import crypto from 'crypto'
import jwt from 'jsonwebtoken'

// Verifies a native "Sign in with Apple" identity token against Apple's published keys.
// Unlike the /api/auth/apple route (one global APPLE_CLIENT_ID), the accepted audiences are passed in
// so each registered app client can name its own bundle ID.

const KEYS_URL = 'https://appleid.apple.com/auth/keys'
const TTL_MS = 60 * 60 * 1000
let cache = null
let cachedAt = 0

async function appleKeys(force = false) {
  if (!force && cache && Date.now() - cachedAt < TTL_MS) return cache
  const res = await fetch(KEYS_URL, { signal: AbortSignal.timeout(5000) })
  if (!res.ok) throw new Error('failed to fetch Apple public keys')
  cache = (await res.json()).keys
  cachedAt = Date.now()
  return cache
}

// -> verified payload, or null if the token is not valid for one of `audiences`
export async function verifyAppleIdentityToken(identityToken, audiences) {
  if (typeof identityToken !== 'string' || !audiences?.length) return null
  let header
  try { header = JSON.parse(Buffer.from(identityToken.split('.')[0], 'base64url').toString()) } catch { return null }

  let jwk = (await appleKeys()).find(k => k.kid === header.kid)
  if (!jwk) jwk = (await appleKeys(true)).find(k => k.kid === header.kid) // Apple rotated keys
  if (!jwk) return null

  try {
    const payload = jwt.verify(identityToken, crypto.createPublicKey({ key: jwk, format: 'jwk' }), {
      algorithms: ['RS256'], issuer: 'https://appleid.apple.com', audience: audiences
    })
    return payload.sub ? payload : null
  } catch { return null }
}

// test hook
export function _reset() { cache = null; cachedAt = 0 }
