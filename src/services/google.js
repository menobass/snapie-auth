import { makeOidcVerifier } from './oidc.js'

// Native Google sign-in ID token (Android Credential Manager / iOS Google Sign-In SDK), verified locally
// against Google's published keys. Audiences are the OAuth client IDs registered for the app client.
const google = makeOidcVerifier({
  keysUrl: 'https://www.googleapis.com/oauth2/v3/certs',
  issuers: ['https://accounts.google.com', 'accounts.google.com']
})

export const verifyGoogleIdToken = google.verify
export const _reset = google.reset // test hook
