import { MongoClient } from 'mongodb'

const uri = process.env.MONGODB_URI
const dbName = process.env.MONGODB_DB || 'snapieauth'

if (!uri) {
  console.error('FATAL: MONGODB_URI is not set')
  process.exit(1)
}

let _client = null
let _db = null

export async function connect() {
  if (_db) return _db
  _client = new MongoClient(uri)
  await _client.connect()
  _db = _client.db(dbName)
  console.log(`MongoDB connected: ${dbName}`)
  return _db
}

export function db() {
  if (!_db) throw new Error('DB not connected — call connect() first')
  return _db
}

export const users = () => db().collection('snapieauth_users')
export const accountJobs = () => db().collection('snapieauth_account_jobs')
export const broadcastLog = () => db().collection('snapieauth_broadcast_log')
export const linkNonces = () => db().collection('snapieauth_link_nonces')
export const sponsorTokens = () => db().collection('snapieauth_sponsor_tokens')
