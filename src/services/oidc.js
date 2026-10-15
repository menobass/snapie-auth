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

  // -> verified payload, or null if the token is not valid for one of `audiences`.
  // `onFail(reason, info)` (optional) is told why a token was refused. `info` only ever carries
  // non-secret claims (aud, iss, exp) and the verifier's error message, never the token itself.
  async function verify(idToken, audiences, onFail = () => {}) {
    if (typeof idToken !== 'string' || !audiences?.length) { onFail('no_token_or_audience'); return null }
    let header
    try { header = JSON.parse(Buffer.from(idToken.split('.')[0], 'base64url').toString()) } catch { onFail('malformed_token'); return null }

    let jwk = (await providerKeys()).find(k => k.kid === header.kid)
    if (!jwk) jwk = (await providerKeys(true)).find(k => k.kid === header.kid) // provider rotated keys
    if (!jwk) { onFail('unknown_key', { kid: header.kid }); return null }

    try {
      const payload = jwt.verify(idToken, crypto.createPublicKey({ key: jwk, format: 'jwk' }), {
        algorithms: ['RS256'], issuer: issuers, audience: audiences
      })
      if (!payload.sub) { onFail('no_subject'); return null }
      return payload
    } catch (err) {
      let claims = {}
      try { claims = jwt.decode(idToken) || {} } catch { /* not decodable */ }
      onFail('verify_failed', { error: err.message, aud: claims.aud, iss: claims.iss, exp: claims.exp })
      return null
    }
  }

  return { verify, reset() { cache = null; cachedAt = 0 } }
}
