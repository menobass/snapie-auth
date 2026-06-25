import { Router } from 'express'
import { ObjectId } from 'mongodb'
import { asyncMw } from '../services/async-middleware.js'
import { authMiddleware } from '../services/auth.js'
import { csrfMiddleware } from '../services/csrf.js'
import { getUserById } from '../services/users.js'
import { broadcastLog } from '../services/db.js'
import {
  isValidPluginId,
  isValidMachineId,
  getOrCreateHiveAccountForLicense,
  broadcastLicenseActivation
} from '../services/license.js'

const router = Router()

async function logLicenseOp(userId, hiveUsername, success, error, ip) {
  await broadcastLog().insertOne({
    userId: new ObjectId(userId),
    hiveUsername: hiveUsername || null,
    opType: 'custom_json',
    opClass: 'license',
    custodyMode: 'custodial',
    txId: null,
    success,
    error: error || null,
    ip,
    createdAt: new Date()
  }).catch(() => {})
}

// POST /api/license/activate
// Plugin-licensing redirect flow: get-or-create the user's custodial Hive
// account, broadcast the pechi_license activation op, return the result so
// the frontend can build the redirect back to the plugin's activation page.
router.post('/activate', authMiddleware, csrfMiddleware, asyncMw(async (req, res) => {
  const { plugin, machine } = req.body

  if (!isValidPluginId(plugin)) {
    return res.status(400).json({ status: 'error', error: 'invalid_plugin' })
  }
  if (!isValidMachineId(machine)) {
    return res.status(400).json({ status: 'error', error: 'invalid_machine' })
  }

  const user = await getUserById(req.user.userId)
  if (!user) return res.status(401).json({ error: 'Unauthorized' })

  const accountResult = await getOrCreateHiveAccountForLicense(user)
  if (accountResult.error) {
    await logLicenseOp(user._id, null, false, accountResult.error, req.ip)
    return res.json({ status: 'error', error: accountResult.error })
  }

  const hiveUsername = accountResult.username
  const broadcastResult = await broadcastLicenseActivation({ hiveUsername, plugin, machine })
  if (broadcastResult.error) {
    await logLicenseOp(user._id, hiveUsername, false, broadcastResult.error, req.ip)
    return res.json({ status: 'error', error: broadcastResult.error })
  }

  await logLicenseOp(user._id, hiveUsername, true, null, req.ip)
  res.json({ status: 'activated', hiveUser: hiveUsername })
}))

export default router
