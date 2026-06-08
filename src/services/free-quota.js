import { db } from './db.js'

const freeQuotas = () => db().collection('snapieauth_free_quotas')

const IP_LIMIT = () => parseInt(process.env.FREE_ACCOUNTS_PER_IP_PER_DAY || '2', 10)
const GLOBAL_LIMIT = () => parseInt(process.env.FREE_ACCOUNTS_GLOBAL_PER_DAY || '10', 10)

function todayUTC() {
  return new Date().toISOString().slice(0, 10) // YYYY-MM-DD
}

function tomorrowMidnightUTC() {
  const d = new Date()
  d.setUTCDate(d.getUTCDate() + 1)
  d.setUTCHours(0, 0, 0, 0)
  return d
}

async function getCount(type, key) {
  const doc = await freeQuotas().findOne({ type, key, date: todayUTC() })
  return doc?.count ?? 0
}

async function increment(type, key) {
  const result = await freeQuotas().findOneAndUpdate(
    { type, key, date: todayUTC() },
    {
      $inc: { count: 1 },
      $setOnInsert: { expiresAt: tomorrowMidnightUTC() }
    },
    { upsert: true, returnDocument: 'after' }
  )
  return result.count
}

async function decrement(type, key) {
  await freeQuotas().updateOne(
    { type, key, date: todayUTC() },
    { $inc: { count: -1 } }
  )
}

// Public quota info — used by /api/quota
export async function getGlobalQuotaInfo() {
  const used = await getCount('global', 'global')
  const total = GLOBAL_LIMIT()
  return {
    total,
    used,
    remaining: Math.max(0, total - used),
    resetsAt: tomorrowMidnightUTC().toISOString()
  }
}

// Read-only check — used by /eligibility
export async function checkFreeQuota(ip) {
  const [ipCount, globalCount] = await Promise.all([
    getCount('ip', ip),
    getCount('global', 'global')
  ])
  if (globalCount >= GLOBAL_LIMIT()) return { allowed: false, reason: 'global_daily_limit' }
  if (ipCount >= IP_LIMIT()) return { allowed: false, reason: 'ip_daily_limit' }
  return { allowed: true, reason: null }
}

// Atomic consume — used by /create (increments counters, rolls back on failure)
export async function consumeFreeQuota(ip) {
  const globalCount = await increment('global', 'global')
  if (globalCount > GLOBAL_LIMIT()) {
    await decrement('global', 'global')
    return { allowed: false, reason: 'global_daily_limit' }
  }

  const ipCount = await increment('ip', ip)
  if (ipCount > IP_LIMIT()) {
    await decrement('ip', ip)
    await decrement('global', 'global')
    return { allowed: false, reason: 'ip_daily_limit' }
  }

  return { allowed: true, reason: null }
}
