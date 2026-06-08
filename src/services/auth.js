import jwt from 'jsonwebtoken'
import fs from 'fs'
import path from 'path'
import crypto from 'crypto'
import { fileURLToPath } from 'url'
import { ObjectId } from 'mongodb'
import { users } from './db.js'

const __dirname = path.dirname(fileURLToPath(import.meta.url))

export const SESSION_COOKIE = 'snapieauth_session'
const SESSION_TTL = parseInt(process.env.SESSION_TTL_SECONDS || '604800', 10)
const COOKIE_MAX_AGE_MS = SESSION_TTL * 1000
const KEY_ID = process.env.JWT_KEY_ID || 'snapie-auth-2026-01'

const PRIVATE_KEY_PATH = process.env.JWT_PRIVATE_KEY_PATH ||
  path.join(__dirname, '..', '..', 'keys', 'jwt-private.pem')
const PUBLIC_KEY_PATH = process.env.JWT_PUBLIC_KEY_PATH ||
  path.join(__dirname, '..', '..', 'keys', 'jwt-public.pem')

let PRIVATE_KEY, PUBLIC_KEY
try {
  PRIVATE_KEY = fs.readFileSync(PRIVATE_KEY_PATH, 'utf8')
  PUBLIC_KEY = fs.readFileSync(PUBLIC_KEY_PATH, 'utf8')
} catch (err) {
  console.error('FATAL: failed to load JWT keys from', PRIVATE_KEY_PATH)
  console.error(err.message)
  process.exit(1)
}

export function createToken(payload) {
  return jwt.sign(payload, PRIVATE_KEY, {
    algorithm: 'RS256',
    expiresIn: SESSION_TTL,
    keyid: KEY_ID
  })
}

export function verifyToken(token) {
  try {
    return jwt.verify(token, PUBLIC_KEY, { algorithms: ['RS256'] })
  } catch {
    return null
  }
}

export function setSessionCookie(res, token) {
  res.cookie(SESSION_COOKIE, token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: COOKIE_MAX_AGE_MS,
    path: '/'
  })
}

export function clearSessionCookie(res) {
  res.clearCookie(SESSION_COOKIE, {
    path: '/',
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    httpOnly: true
  })
}

export async function bumpSessionMinIat(userId) {
  const now = Math.floor(Date.now() / 1000)
  await users().updateOne({ _id: toOid(userId) }, { $set: { sessionMinIat: now } })
}

export function toOid(id) {
  if (id instanceof ObjectId) return id
  if (typeof id === 'string' && /^[0-9a-fA-F]{24}$/.test(id)) return new ObjectId(id)
  return null
}

export async function authMiddleware(req, res, next) {
  let token = null
  if (req.cookies?.[SESSION_COOKIE]) {
    token = req.cookies[SESSION_COOKIE]
  } else if (req.headers.authorization?.startsWith('Bearer ')) {
    token = req.headers.authorization.slice(7)
  }

  if (!token) return res.status(401).json({ error: 'Unauthorized' })

  const decoded = verifyToken(token)
  if (!decoded) return res.status(401).json({ error: 'Unauthorized' })

  // Only accept session tokens — reject untyped or other types
  if (decoded.type !== 'session') return res.status(401).json({ error: 'Unauthorized' })

  if (typeof decoded.userId !== 'string') return res.status(401).json({ error: 'Unauthorized' })

  const oid = toOid(decoded.userId)
  if (!oid) return res.status(401).json({ error: 'Unauthorized' })

  const row = await users().findOne({ _id: oid }, { projection: { sessionMinIat: 1, isAdmin: 1 } })
  if (!row) return res.status(401).json({ error: 'Unauthorized' })

  if ((row.sessionMinIat || 0) > (decoded.iat || 0)) {
    return res.status(401).json({ error: 'Session revoked' })
  }

  req.user = decoded
  req.user.isAdmin = row.isAdmin || false
  next()
}

export function getPublicKey() {
  return PUBLIC_KEY
}
