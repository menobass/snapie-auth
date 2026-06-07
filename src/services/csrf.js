import crypto from 'crypto'

export const CSRF_COOKIE = 'snapieauth_csrf'
const COOKIE_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000

export function setCsrfCookie(res) {
  const token = crypto.randomBytes(24).toString('hex')
  res.cookie(CSRF_COOKIE, token, {
    httpOnly: false,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: COOKIE_MAX_AGE_MS,
    path: '/'
  })
  return token
}

export function clearCsrfCookie(res) {
  res.clearCookie(CSRF_COOKIE, {
    path: '/',
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax'
  })
}

export function csrfMiddleware(req, res, next) {
  const cookie = req.cookies?.[CSRF_COOKIE]
  const header = req.headers['x-csrf-token']
  if (!cookie || !header) {
    return res.status(403).json({ error: 'CSRF check failed' })
  }
  try {
    const a = Buffer.from(cookie)
    const b = Buffer.from(header)
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      return res.status(403).json({ error: 'CSRF check failed' })
    }
  } catch {
    return res.status(403).json({ error: 'CSRF check failed' })
  }
  next()
}
