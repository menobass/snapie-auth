import 'dotenv/config'
import { fileURLToPath } from 'url'
import { join, dirname } from 'path'
import express from 'express'
import helmet from 'helmet'
import cors from 'cors'
import cookieParser from 'cookie-parser'
import { rateLimit } from 'express-rate-limit'
import { connect } from './services/db.js'
import { ensureIndexes } from './db/init.js'
import { startReconcileLoop } from './services/account-jobs.js'
import { startPaymentPollLoop } from './services/payment.js'
import { getGlobalQuotaInfo } from './services/free-quota.js'
import authRoutes from './routes/auth.js'
import accountRoutes from './routes/account.js'
import linkRoutes from './routes/link.js'
import hiveRoutes from './routes/hive.js'
import emancipateRoutes from './routes/emancipate.js'
import adminRoutes from './routes/admin.js'
import internalRoutes from './routes/internal.js'
import paymentRoutes from './routes/payment.js'
import licenseRoutes from './routes/license.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const PUBLIC_DIR = join(__dirname, '..', 'public')

const app = express()
const PORT = parseInt(process.env.PORT || '3500', 10)

// CORS — comma-separated FRONTEND_URL
const allowedOrigins = (process.env.FRONTEND_URL || '')
  .split(',')
  .map(o => o.trim())
  .filter(Boolean)

app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true)
    } else {
      callback(new Error(`CORS: origin ${origin} not allowed`))
    }
  },
  credentials: true
}))

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", 'accounts.google.com'],
      styleSrc: ["'self'", "'unsafe-inline'", 'fonts.googleapis.com'],
      fontSrc: ["'self'", 'fonts.gstatic.com'],
      imgSrc: ["'self'", 'data:', 'https:'],
      connectSrc: ["'self'", 'https://accounts.google.com', 'https://oauth2.googleapis.com']
    }
  }
}))
app.use(express.json({ limit: '64kb' }))
app.use(cookieParser())
app.use(express.static(PUBLIC_DIR))

// Trust proxy for accurate req.ip behind nginx
app.set('trust proxy', 1)

// ── Rate limiters ──────────────────────────────────────────────
const rl = (windowMs, max) => rateLimit({
  windowMs,
  max,
  standardHeaders: true,
  legacyHeaders: false
})

const authLimiter     = rl(15 * 60 * 1000,  30)   // 30/15min
const resendLimiter   = rl(60 * 60 * 1000,  5)    // 5/hr
const createLimiter   = rl(60 * 60 * 1000,  5)    // 5/hr
const checkLimiter    = rl(60 * 1000,        40)   // 40/min
const broadcastLimiter= rl(60 * 1000,        60)   // 60/min
const signLimiter     = rl(60 * 1000,        30)   // 30/min
const transferLimiter = rl(60 * 1000,        10)   // 10/min
const emancLimiter    = rl(60 * 60 * 1000,  5)    // 5/hr
const licenseLimiter  = rl(60 * 1000,        10)   // 10/min

// ── Routes ────────────────────────────────────────────────────
app.use('/api/auth/email/resend',      resendLimiter)
app.use('/api/auth',                  authLimiter, authRoutes)
app.use('/api/account/create',        createLimiter)
app.use('/api/account/check-username',checkLimiter)
app.use('/api/account',              accountRoutes)
app.use('/api/link',                 linkRoutes)
app.use('/api/hive/limit-order-create',   transferLimiter)
app.use('/api/hive/limit-order-cancel',   transferLimiter)
app.use('/api/hive/broadcast',            broadcastLimiter)
app.use('/api/hive/sign-message',         signLimiter)
app.use('/api/hive/transfer',             transferLimiter)
app.use('/api/hive/transfer-to-savings',  transferLimiter)
app.use('/api/hive/transfer-from-savings',transferLimiter)
app.use('/api/hive/convert',              transferLimiter)
app.use('/api/hive/collateralized-convert',transferLimiter)
app.use('/api/hive',                      hiveRoutes)
app.use('/api/emancipate',           emancLimiter, emancipateRoutes)
app.use('/api/admin',                adminRoutes)
app.use('/api/internal',             internalRoutes)
app.use('/api/payment',              paymentRoutes)
app.use('/api/license/activate',     licenseLimiter)
app.use('/api/license',              licenseRoutes)

// Plugin-licensing redirect entry point — see internal-docs/HANDOFF_SNAPIE_REDIRECT.md
// (login-callback.html is served directly by express.static below, like manage.html/docs.html)
app.get('/login', (_req, res) => res.sendFile(join(PUBLIC_DIR, 'login.html')))

// Public quota — how many free account slots remain today
app.get('/api/quota', async (_req, res, next) => {
  try {
    res.json(await getGlobalQuotaInfo())
  } catch (e) { next(e) }
})

// Public config — exposes non-secret config to the frontend
app.get('/api/public-config', (_req, res) => {
  res.json({
    googleClientId: process.env.GOOGLE_CLIENT_ID || null,
    hiveNetwork: process.env.HIVE_NETWORK || 'mainnet',
    discordUrl: 'https://discord.gg/CgJP7t7nWy',
    licenseRedirectHosts: (process.env.LICENSE_REDIRECT_HOSTS || 'licensing.menosoft.xyz')
      .split(',').map(h => h.trim()).filter(Boolean)
  })
})

// Health check
app.get('/health', (_req, res) => res.json({ ok: true }))

// Global error handler
app.use((err, req, res, _next) => {
  if (err.message?.startsWith('CORS:')) {
    return res.status(403).json({ error: err.message })
  }
  console.error(err)
  res.status(500).json({ error: 'internal_server_error' })
})

// ── Startup ───────────────────────────────────────────────────
async function start() {
  await connect()
  await ensureIndexes()
  startReconcileLoop()
  startPaymentPollLoop()
  app.listen(PORT, () => console.log(`snapie-auth listening on port ${PORT}`))
}

start().catch(err => {
  console.error('Startup failed:', err)
  process.exit(1)
})
