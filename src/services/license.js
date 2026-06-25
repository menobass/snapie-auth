import crypto from 'crypto'
import { accountJobs } from './db.js'
import { getAccount, broadcastOps, hiveErr, isRcError } from './hive.js'
import { isValidHiveUsername, checkUsernameAvailability, createJob } from './account-jobs.js'

const POLL_INTERVAL_MS = 1000
const POLL_TIMEOUT_MS = 25000
const USERNAME_SUFFIX_BYTES = 3 // 6 hex chars

export function isValidPluginId(plugin) {
  return typeof plugin === 'string' && /^[a-z0-9_]{1,64}$/i.test(plugin)
}

export function isValidMachineId(machine) {
  return typeof machine === 'string' && /^[0-9a-f]{16}$/i.test(machine)
}

// Slugifies a display name into a Hive-username-safe base, leaving room for
// a random suffix. Falls back to 'user' when the name has no usable letters.
// Hive usernames are capped at 16 chars; the suffix appended by generateUsername
// is 7 chars ("-" + 6 hex), so the base is capped at 9 to stay within the limit.
const USERNAME_BASE_MAX_LEN = 9

export function slugifyUsernameBase(displayName) {
  const slug = (displayName || '')
    .toLowerCase()
    .normalize('NFKD').replace(/[\u0300-\u036f]/g, '') // strip accents
    .replace(/[^a-z0-9-]/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, USERNAME_BASE_MAX_LEN)
    .replace(/-$/, '')

  if (slug.length >= 3 && /^[a-z]/.test(slug)) return slug
  return 'user'
}

export function generateUsername(displayName) {
  const base = slugifyUsernameBase(displayName)
  const suffix = crypto.randomBytes(USERNAME_SUFFIX_BYTES).toString('hex')
  return `${base}-${suffix}`
}

async function pollJobUntilDone(jobId) {
  const deadline = Date.now() + POLL_TIMEOUT_MS
  while (Date.now() < deadline) {
    const job = await accountJobs().findOne({ _id: jobId })
    if (!job) return { error: 'job_not_found' }
    if (job.status === 'confirmed') return { username: job.username }
    if (job.status === 'failed' || job.status === 'expired') return { error: job.lastError || job.status }
    await new Promise(r => setTimeout(r, POLL_INTERVAL_MS))
  }
  return { error: 'timeout' }
}

// Reuses the existing custodial account if the user already has one
// (returning-user / second-plugin case from the handoff). Otherwise
// generates a username, queues an account-creation job via the existing
// account-jobs pipeline, and polls until it's confirmed on-chain.
export async function getOrCreateHiveAccountForLicense(user) {
  if (user.hiveUsername) return { username: user.hiveUsername }

  const snapieAccount = await getAccount(process.env.SNAPIE_ACCOUNT)
  if (!snapieAccount || (snapieAccount.pending_claimed_accounts || 0) === 0) {
    return { error: 'no_acts' }
  }

  let username = null
  for (let attempt = 0; attempt < 5; attempt++) {
    const candidate = generateUsername(user.name)
    if (!isValidHiveUsername(candidate)) continue
    const avail = await checkUsernameAvailability(candidate)
    if (avail.available) {
      username = candidate
      break
    }
  }
  if (!username) return { error: 'username_generation_failed' }

  const job = await createJob({
    userId: user._id.toString(),
    username,
    custodyMode: 'custodial'
  })

  return pollJobUntilDone(job._id)
}

export async function broadcastLicenseActivation({ hiveUsername, plugin, machine }) {
  const op = ['custom_json', {
    required_auths: [],
    required_posting_auths: [hiveUsername],
    id: 'pechi_license',
    json: JSON.stringify({ op: 'activate', plugin, machine_id: machine })
  }]

  try {
    const result = await broadcastOps([op], process.env.SNAPIE_POSTING_KEY)
    return { txId: result.id }
  } catch (err) {
    if (isRcError(err)) return { error: 'insufficient_rc' }
    return { error: hiveErr(err) }
  }
}
