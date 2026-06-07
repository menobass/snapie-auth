import crypto from 'crypto'
import { sponsorTokens } from './db.js'
import { hashEmail } from './users.js'

// Issue a sponsor token for a specific email.
// issuedBy: 'admin' | 'internal-api'
// expiresInDays: optional, defaults to no expiry
export async function issueToken({ email, note = null, issuedBy, issuedByUserId = null, expiresInDays = null }) {
  const token = crypto.randomUUID()
  const emailHash = hashEmail(email)
  const now = new Date()

  const doc = {
    _id: token,
    emailHash,
    note,
    issuedBy,
    issuedByUserId: issuedByUserId || null,
    expiresAt: expiresInDays ? new Date(now.getTime() + expiresInDays * 86400_000) : null,
    usedAt: null,
    usedByUserId: null,
    createdAt: now
  }

  await sponsorTokens().insertOne(doc)
  return doc
}

// Find a valid (unused, unexpired) sponsor token for this emailHash.
export async function findValidToken(emailHash) {
  return sponsorTokens().findOne({
    emailHash,
    usedAt: null,
    $or: [
      { expiresAt: null },
      { expiresAt: { $gt: new Date() } }
    ]
  })
}

// Consume a token — marks it used. Call inside account creation.
export async function consumeToken(tokenId, usedByUserId) {
  await sponsorTokens().updateOne(
    { _id: tokenId, usedAt: null },
    { $set: { usedAt: new Date(), usedByUserId } }
  )
}

// Revoke (hard-delete) an unused token. Admins only.
export async function revokeToken(tokenId) {
  const result = await sponsorTokens().deleteOne({ _id: tokenId, usedAt: null })
  return result.deletedCount === 1
}

export async function listTokens({ limit = 100, includeUsed = true } = {}) {
  const filter = includeUsed ? {} : { usedAt: null }
  return sponsorTokens()
    .find(filter)
    .sort({ createdAt: -1 })
    .limit(limit)
    .toArray()
}
