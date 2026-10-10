import crypto from 'crypto'
import jwt from 'jsonwebtoken'

// Verifies an OpenID Connect ID token (Apple, Google, ...) against the provider's published JWKS.
// Accepted audiences are passed per call, so each registered app client names its own client IDs.
export function makeOidcVerifier({ keysUrl, issuers }) {
  const TTL_MS = 60 * 60 * 1000
  let cache = null
  let cachedAt = 0

  async function providerKeys(force = false) {
    if (!force && cache && Date.now() - cachedAt < TTL_MS) return cache
    const res = await fetch(keysUrl, { signal: AbortSignal.timeout(5000) })
    if (!res.ok) throw new Error('failed to fetch provider public keys')
    cache = (await res.json()).keys
    cachedAt = Date.now()
    return cache
  }

  // -> verified payload, or null if the token is not valid for one of `audiences`
  async function verify(idToken, audiences) {
    if (typeof idToken !== 'string' || !audiences?.length) return null
    let header
    try { header = JSON.parse(Buffer.from(idToken.split('.')[0], 'base64url').toString()) } catch { return null }

    let jwk = (await providerKeys()).find(k => k.kid === header.kid)
    if (!jwk) jwk = (await providerKeys(true)).find(k => k.kid === header.kid) // provider rotated keys
    if (!jwk) return null

    try {
      const payload = jwt.verify(idToken, crypto.createPublicKey({ key: jwk, format: 'jwk' }), {
        algorithms: ['RS256'], issuer: issuers, audience: audiences
      })
      return payload.sub ? payload : null
    } catch { return null }
  }

  return { verify, reset() { cache = null; cachedAt = 0 } }
}
