import { makeOidcVerifier } from './oidc.js'

// Native "Sign in with Apple" identity token. Unlike the /api/auth/apple route (one global
// APPLE_CLIENT_ID), the accepted audiences (bundle IDs) are passed in per app client.
const apple = makeOidcVerifier({ keysUrl: 'https://appleid.apple.com/auth/keys', issuers: ['https://appleid.apple.com'] })

export const verifyAppleIdentityToken = apple.verify
export const _reset = apple.reset // test hook
