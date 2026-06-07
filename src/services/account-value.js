import { getAccount, client } from './hive.js'

let _cachedPrice = null
let _cacheTime = 0
const PRICE_CACHE_MS = 60_000

async function getHivePrice() {
  const now = Date.now()
  if (_cachedPrice !== null && now - _cacheTime < PRICE_CACHE_MS) return _cachedPrice

  const feed = process.env.HIVE_PRICE_FEED || 'coingecko'

  try {
    if (feed === 'coingecko') {
      const res = await fetch(
        'https://api.coingecko.com/api/v3/simple/price?ids=hive&vs_currencies=usd',
        { headers: { Accept: 'application/json' }, signal: AbortSignal.timeout(5000) }
      )
      const data = await res.json()
      _cachedPrice = data?.hive?.usd || 0
    } else {
      // hive-internal: read the median price from the witness feed
      const feed = await client.database.getCurrentMedianHistoryPrice()
      // feed.base is "X HBD", feed.quote is "Y HIVE"
      const base = parseFloat(feed.base.split(' ')[0])
      const quote = parseFloat(feed.quote.split(' ')[0])
      _cachedPrice = quote > 0 ? base / quote : 0
    }
  } catch (e) {
    console.error('price feed error:', e.message)
    _cachedPrice = _cachedPrice || 0
  }

  _cacheTime = now
  return _cachedPrice
}

// Convert VESTS to HIVE using global props
async function vestsToHive(vestStr) {
  try {
    const vests = parseFloat(vestStr)
    const props = await client.database.getDynamicGlobalProperties()
    const totalVests = parseFloat(props.total_vesting_shares)
    const totalHive = parseFloat(props.total_vesting_fund_hive)
    return totalVests > 0 ? (vests / totalVests) * totalHive : 0
  } catch {
    return 0
  }
}

export async function getAccountValue(hiveUsername) {
  const [account, hivePrice] = await Promise.all([
    getAccount(hiveUsername),
    getHivePrice()
  ])

  if (!account) return null

  const hiveBalance = parseFloat(account.balance)
  const hbdBalance = parseFloat(account.hbd_balance)
  const vestingShares = account.vesting_shares
  const vestingHive = await vestsToHive(vestingShares)

  // HBD is pegged to $1
  const hiveValueUsd = hiveBalance * hivePrice
  const hbdValueUsd = hbdBalance
  const vestingValueUsd = vestingHive * hivePrice
  const totalValueUsd = hiveValueUsd + hbdValueUsd + vestingValueUsd

  return {
    hiveUsername,
    hiveBalance: account.balance,
    hbdBalance: account.hbd_balance,
    vestingShares,
    hiveValueUsd: +hiveValueUsd.toFixed(2),
    hbdValueUsd: +hbdValueUsd.toFixed(2),
    vestingValueUsd: +vestingValueUsd.toFixed(2),
    totalValueUsd: +totalValueUsd.toFixed(2)
  }
}

export function isEmancipationRequired(custodyMode, totalValueUsd) {
  const threshold = parseFloat(process.env.EMANCIPATION_THRESHOLD_USD || '10')
  if (threshold === 0) return false
  return custodyMode === 'custodial' && totalValueUsd >= threshold
}
