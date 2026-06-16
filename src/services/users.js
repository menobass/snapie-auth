import crypto from 'crypto'
import { ObjectId } from 'mongodb'
import { users } from './db.js'
import { createToken, setSessionCookie, toOid } from './auth.js'
import { setCsrfCookie } from './csrf.js'

const PEPPER = process.env.KEY_ENCRYPTION_PEPPER || ''

export function hashEmail(email) {
  return crypto.createHmac('sha256', PEPPER).update(email.toLowerCase().trim()).digest('hex')
}

export async function upsertUser({ provider, providerId, emailHash, name, picture, emailVerified }) {
  const now = new Date()
  // Only overwrite name/picture when the provider actually supplies them.
  // Apple sends them only on first sign-in; omitting here preserves the saved value on re-logins.
  const setFields = { updatedAt: now }
  if (provider !== 'email' && name) setFields.name = name
  if (provider !== 'email' && picture) setFields.picture = picture

  const result = await users().findOneAndUpdate(
    { provider, providerId },
    {
      $set: setFields,
      $setOnInsert: {
        ...(!setFields.name && { name: null }),
        ...(!setFields.picture && { picture: null }),
        provider,
        providerId,
        emailHash: emailHash || null,
        // hiveUsername intentionally omitted — sparse unique index skips absent fields;
        // setting null would be indexed and block a second email-only user
        custodyMode: null,
        encryptedKeys: null,
        passwordHash: null,
        emailVerified: emailVerified ?? true,
        everHadAccount: false,
        sessionMinIat: 0,
        emancipatedAt: null,
        emancipationForcedAt: null,
        isAdmin: false,
        createdAt: now
      }
    },
    { upsert: true, returnDocument: 'after' }
  )
  return result
}

export async function getUserById(id) {
  const oid = toOid(id)
  if (!oid) return null
  return users().findOne({ _id: oid })
}

export async function clearPaidAccountCreation(id) {
  const oid = toOid(id)
  if (!oid) return
  await users().updateOne({ _id: oid }, { $unset: { hasPaidAccountCreation: '' } })
}

export function shapeUser(user, extra = {}) {
  return {
    id: user._id.toString(),
    provider: user.provider || null,
    name: user.name || null,
    picture: user.picture || null,
    hiveUsername: user.hiveUsername || null,
    custodyMode: user.custodyMode || null,
    isAdmin: user.isAdmin || false,
    ...extra
  }
}

export function startSession(res, user, email) {
  const token = createToken({
    type: 'session',
    userId: user._id.toString(),
    email: email || null,
    name: user.name || null,
    picture: user.picture || null
  })
  setSessionCookie(res, token)
  setCsrfCookie(res)
  return shapeUser(user)
}
