import { db } from '../services/db.js'

export async function ensureIndexes() {
  const database = db()

  await Promise.all([
    // snapieauth_users
    database.collection('snapieauth_users').createIndex(
      { provider: 1, providerId: 1 }, { unique: true }
    ),
    database.collection('snapieauth_users').createIndex(
      { hiveUsername: 1 }, { unique: true, sparse: true }
    ),
    database.collection('snapieauth_users').createIndex(
      { emailHash: 1 }, { sparse: true }
    ),

    // snapieauth_account_jobs
    database.collection('snapieauth_account_jobs').createIndex({ userId: 1 }),
    database.collection('snapieauth_account_jobs').createIndex(
      { liveUsername: 1 }, { unique: true, sparse: true }
    ),
    database.collection('snapieauth_account_jobs').createIndex({ status: 1 }),
    database.collection('snapieauth_account_jobs').createIndex(
      { expiresAt: 1 }, { expireAfterSeconds: 0 }
    ),

    // snapieauth_broadcast_log
    database.collection('snapieauth_broadcast_log').createIndex(
      { userId: 1, createdAt: -1 }
    ),

    // snapieauth_link_nonces — TTL 5 min
    database.collection('snapieauth_link_nonces').createIndex({ nonce: 1 }, { unique: true }),
    database.collection('snapieauth_link_nonces').createIndex(
      { createdAt: 1 }, { expireAfterSeconds: 300 }
    ),

    // snapieauth_sponsor_tokens
    // emailHash is not unique — an admin can issue multiple tokens to the same email
    // (e.g. user earned it twice, one was revoked). Only one can be redeemed though.
    database.collection('snapieauth_sponsor_tokens').createIndex({ emailHash: 1 }),
    database.collection('snapieauth_sponsor_tokens').createIndex({ usedAt: 1 }),
    database.collection('snapieauth_sponsor_tokens').createIndex(
      { expiresAt: 1 }, { expireAfterSeconds: 0, sparse: true }
    ),

    // snapieauth_email_verifications — pending email verification tokens
    database.collection('snapieauth_email_verifications').createIndex(
      { token: 1 }, { unique: true }
    ),
    database.collection('snapieauth_email_verifications').createIndex(
      { expiresAt: 1 }, { expireAfterSeconds: 0 }
    ),

    // snapieauth_free_quotas — daily IP and global account creation counters
    database.collection('snapieauth_free_quotas').createIndex(
      { type: 1, key: 1, date: 1 }, { unique: true }
    ),
    database.collection('snapieauth_free_quotas').createIndex(
      { expiresAt: 1 }, { expireAfterSeconds: 0 }
    ),
  ])

  console.log('MongoDB indexes ensured')
}
