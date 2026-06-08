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
  const result = await users().findOneAndUpdate(
    { provider, providerId },
    {
      $set: {
        name: provider !== 'email' ? (name || null) : null,
        picture: provider !== 'email' ? (picture || null) : null,
        updatedAt: now
      },
      $setOnInsert: {
        provider,
        providerId,
        emailHash: emailHash || null,
        hiveUsername: null,
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

export function shapeUser(user, extra = {}) {
  return {
    id: user._id.toString(),
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
