import { Router } from 'express'
import { asyncMw } from '../services/async-middleware.js'
import { authMiddleware } from '../services/auth.js'
import { csrfMiddleware } from '../services/csrf.js'
import { getUserById } from '../services/users.js'
import { deriveServerKey, decryptKey, verifyDecryptedKeys } from '../services/key-crypto.js'
import { getAccountValue, isEmancipationRequired } from '../services/account-value.js'
import { getAccount } from '../services/hive.js'
import { users } from '../services/db.js'

const router = Router()

// GET /api/emancipate/status
router.get('/status', authMiddleware, asyncMw(async (req, res) => {
  const user = await getUserById(req.user.userId)
  if (!user) return res.status(401).json({ error: 'Unauthorized' })

  const threshold = parseFloat(process.env.EMANCIPATION_THRESHOLD_USD || '10')
  let accountValueUsd = null

  if (user.hiveUsername) {
    try {
      const value = await getAccountValue(user.hiveUsername)
      if (value) accountValueUsd = value.totalValueUsd
    } catch {
      // non-fatal
    }
  }

  res.json({
    custodyMode: user.custodyMode,
    accountValueUsd,
    threshold,
    forcedEmancipation: isEmancipationRequired(user.custodyMode, accountValueUsd || 0),
    hiveUsername: user.hiveUsername || null
  })
}))

// POST /api/emancipate/start
// No password needed — server derives the key from its own pepper + userId.
// Identity is proven by the Google session already.
router.post('/start', authMiddleware, csrfMiddleware, asyncMw(async (req, res) => {
  const user = await getUserById(req.user.userId)
  if (!user) return res.status(401).json({ error: 'Unauthorized' })

  if (user.custodyMode !== 'custodial') {
    return res.status(400).json({ error: 'not_custodial' })
  }
  if (!user.encryptedKeys) {
    return res.status(400).json({ error: 'no_encrypted_keys' })
  }
  if (!user.hiveUsername) {
    return res.status(400).json({ error: 'no_hive_account' })
  }

  // Derive the server-side key — deterministic from pepper + userId
  const serverKey = deriveServerKey(user._id.toString())

  // Decrypt all four keys
  let decryptedKeys
  try {
    decryptedKeys = {
      owner:   decryptKey(user.encryptedKeys.owner,   serverKey),
      active:  decryptKey(user.encryptedKeys.active,  serverKey),
      posting: decryptKey(user.encryptedKeys.posting, serverKey),
      memo:    decryptKey(user.encryptedKeys.memo,    serverKey)
    }
  } catch {
    return res.status(500).json({ error: 'decryption_failed' })
  }

  // Verify decrypted keys match on-chain (proves we stored them correctly)
  const onChainAccount = await getAccount(user.hiveUsername)
  if (!onChainAccount) {
    return res.status(500).json({ error: 'account_not_found_on_chain' })
  }
  if (!verifyDecryptedKeys(decryptedKeys, onChainAccount)) {
    return res.status(500).json({ error: 'key_verification_failed' })
  }

  // Wipe encrypted keys from DB immediately — this is the point of no return
  await users().updateOne(
    { _id: user._id },
    {
      $set: {
        custodyMode: 'emancipated',
        encryptedKeys: null,
        emancipatedAt: new Date(),
        updatedAt: new Date()
      }
    }
  )

  res.json({
    keys: decryptedKeys,
    message: 'Save these keys now. They will not be shown again. This server has deleted its copy.'
  })
}))

// POST /api/emancipate/confirm
// Client confirms they have saved the keys — ensures cleanup is complete
router.post('/confirm', authMiddleware, csrfMiddleware, asyncMw(async (req, res) => {
  const user = await getUserById(req.user.userId)
  if (!user) return res.status(401).json({ error: 'Unauthorized' })

  await users().updateOne(
    { _id: user._id },
    {
      $set: {
        custodyMode: 'emancipated',
        encryptedKeys: null,
        emancipatedAt: user.emancipatedAt || new Date(),
        updatedAt: new Date()
      }
    }
  )

  res.json({ ok: true })
}))

export default router
