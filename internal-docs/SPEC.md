# snapie-auth — Build Specification

> A purpose-built auth + signing service for Snapie. Bridges Google OAuth to Hive accounts, manages custodial key storage, and acts as the sole signing proxy between the Snapie frontend and the Hive blockchain.

---

## 1. What This Is

snapie-auth is a small Express + MongoDB service that runs on the Snapie VPS. It does four things:

1. **Identity**: Google OAuth login → persistent user session (httpOnly cookie + JWT)
2. **Account creation**: Browser generates keys client-side → service creates the Hive account using its own claimed ACTs → posting authority to `@snapie` is baked in at creation
3. **Signing proxy**: All Hive operations from the frontend come here. The service decides how to sign them based on operation type and the user's custody mode.
4. **Custody + emancipation**: Optionally stores all four user keys encrypted with Argon2 (derived from user's password). Forces emancipation when account value crosses a configured threshold.

**What it is NOT**: a general-purpose OAuth server. It has no app registration, no multi-tenant federation, no public SDK. It serves one frontend: the Snapie Next.js app.

---

## 2. Tech Stack

- **Runtime**: Node.js ≥ 18, ESM (`"type": "module"`)
- **Framework**: Express 4
- **Database**: MongoDB (URI provided via env — uses existing VPS instance)
- **Hive client**: `@hiveio/dhive`
- **Key encryption**: `argon2` npm package (Argon2id)
- **JWT**: `jsonwebtoken` with RS256 (generate keypair at setup)
- **Google auth**: verify Google ID token via `https://oauth2.googleapis.com/tokeninfo?id_token=<token>` (no extra Google SDK needed)
- **Rate limiting**: `express-rate-limit`
- **Security headers**: `helmet`
- **Password hashing** (for email+password login): `argon2`
- **CSRF**: double-submit cookie pattern (same as butrauth — see Section 10)

Generate JWT keys at setup:
```bash
mkdir -p keys
openssl genpkey -algorithm RSA -out keys/jwt-private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -in keys/jwt-private.pem -pubout -out keys/jwt-public.pem
```

---

## 3. Environment Variables

```env
# Server
PORT=3500
NODE_ENV=production
FRONTEND_URL=https://snapie.io
# Comma-separated if multiple (e.g. local dev + prod)
# FRONTEND_URL=https://snapie.io,http://localhost:3000

# MongoDB
MONGODB_URI=mongodb://user:pass@localhost:27017/snapieauth?authSource=admin
MONGODB_DB=snapieauth

# JWT (RS256)
JWT_PRIVATE_KEY_PATH=./keys/jwt-private.pem
JWT_PUBLIC_KEY_PATH=./keys/jwt-public.pem
JWT_KEY_ID=snapie-auth-2026-01
# Session TTL in seconds. Default 7 days.
SESSION_TTL_SECONDS=604800

# Google OAuth
# Create at: https://console.cloud.google.com/apis/credentials
# Add your domain as an authorized JavaScript origin.
GOOGLE_CLIENT_ID=

# Hive — the Snapie service account
# This account must have pending_claimed_accounts > 0 (run claim_account ops)
SNAPIE_ACCOUNT=snapie
SNAPIE_ACTIVE_KEY=5J...         # Active key of @snapie — for create_claimed_account
SNAPIE_POSTING_KEY=5K...        # Posting key of @snapie — for broadcasting posting-level ops + RC delegation
HIVE_NODES=https://api.hive.blog,https://api.deathwing.me,https://api.openhive.network
HIVE_NETWORK=mainnet            # mainnet | testnet

# RC delegation: every new account gets this many Bn RC delegated from @snapie
# Minimum 5 (Ecency's floor). delegate_rc uses SNAPIE_POSTING_KEY.
RC_DELEGATION_BN=5

# Custodial key encryption pepper — random 32-byte hex, never changes after first deploy
# Generate: openssl rand -hex 32
KEY_ENCRYPTION_PEPPER=

# Emancipation threshold in USD. When account value >= this, user is forced to emancipate.
# Set to 0 to disable forced emancipation (manual only).
EMANCIPATION_THRESHOLD_USD=10

# Hive price feed (for emancipation threshold check). Used to convert HIVE → USD.
# Options: coingecko | hive-internal (uses @hive.fund witness feed)
HIVE_PRICE_FEED=coingecko

# Account reconciliation interval in ms
ACCOUNT_RECONCILE_INTERVAL_MS=5000
```

---

## 4. MongoDB Schema

Database name from `MONGODB_DB`. All collections are prefixed with `snapieauth_` to avoid collisions if the DB is shared.

### `snapieauth_users`

```js
{
  _id: ObjectId,
  // Auth identity
  provider: 'google' | 'email',
  providerId: String,           // Google sub, or argon2(email) for email provider
  emailHash: String,            // HMAC-SHA256(KEY_ENCRYPTION_PEPPER, email) — never store plaintext
  name: String | null,          // Display name from Google. Null for email provider.
  picture: String | null,       // Avatar URL from Google.

  // Hive
  hiveUsername: String | null,  // Set once account is confirmed on-chain. Null until then.
  custodyMode: 'custodial' | 'emancipated' | null,  // null until account exists

  // Custodial key storage — only present if custodyMode === 'custodial'
  // Each value is: { iv: hex, ciphertext: hex } — Argon2id(password+pepper) → AES-256-GCM
  encryptedKeys: {
    owner:   { iv: String, ciphertext: String } | null,
    active:  { iv: String, ciphertext: String } | null,
    posting: { iv: String, ciphertext: String } | null,
    memo:    { iv: String, ciphertext: String } | null,
  } | null,

  // For email+password auth: the user's password hash (Argon2id)
  // This is ALSO the key used to derive the key encryption key.
  passwordHash: String | null,

  // Anti-farming: once a user has ever had a Hive account linked here,
  // they cannot create another free one (must pay). Never unset.
  everHadAccount: Boolean,

  // Session invalidation: sessions issued before this timestamp are rejected.
  sessionMinIat: Number,        // Unix timestamp seconds. Default 0.

  // Emancipation state
  emancipatedAt: Date | null,
  emancipationForcedAt: Date | null,  // Set when forced by value threshold

  isAdmin: Boolean,
  createdAt: Date,
  updatedAt: Date,
}
```

**Indexes**:
- `{ provider: 1, providerId: 1 }` — unique
- `{ hiveUsername: 1 }` — sparse unique (only set once account exists)
- `{ emailHash: 1 }` — sparse (for email login dedup)

### `snapieauth_account_jobs`

```js
{
  _id: String,                  // crypto.randomUUID()
  userId: ObjectId,             // ref snapieauth_users._id
  username: String,             // desired Hive username (lowercase)
  liveUsername: String,         // same as username while job is active (sparse-unique index reserves it)

  // Keys — only public keys ever leave the browser
  ownerPub: String,
  activePub: String,
  postingPub: String,
  memoPub: String,

  // Whether user chose custodial (keys will be stored encrypted after confirmation)
  custodyMode: 'custodial' | 'emancipated',
  // For custodial: the encrypted key blobs — populated AFTER on-chain confirmation
  encryptedKeys: Object | null,

  status: 'pending' | 'broadcasting' | 'acked' | 'confirmed' | 'failed' | 'expired',
  txId: String | null,
  ackAt: Date | null,
  confirmedAt: Date | null,
  failedAt: Date | null,
  lastError: String | null,
  attempts: Number,
  createdAt: Date,
  expiresAt: Date,              // 30 min from creation
}
```

**Indexes**:
- `{ userId: 1 }`
- `{ liveUsername: 1 }` — sparse unique (only present while status is active)
- `{ status: 1 }`
- `{ expiresAt: 1 }` — for TTL cleanup

### `snapieauth_broadcast_log`

Append-only log of every Hive operation signed by this service. Used for auditing and abuse detection.

```js
{
  _id: ObjectId,
  userId: ObjectId,
  hiveUsername: String,
  opType: String,               // 'vote', 'comment', 'transfer', etc.
  opClass: 'posting' | 'active',
  custodyMode: 'custodial' | 'emancipated',
  txId: String | null,
  success: Boolean,
  error: String | null,
  ip: String,
  createdAt: Date,
}
```

**Index**: `{ userId: 1, createdAt: -1 }`

---

## 5. Hive Operation Classes

This is the routing table the signing service uses. Every op falls into one of two classes:

**Posting-level** (sign with `SNAPIE_POSTING_KEY` — works for ALL users):
- `vote`
- `comment` (posts and replies)
- `delete_comment`
- `custom_json` (follow, reblog, community actions, etc.)
- `claim_reward_balance`

**Active-level** (custodial users only — sign with decrypted user active key; emancipated users get unsigned op back):
- `transfer`
- `transfer_to_vesting` (power up)
- `withdraw_vesting` (power down)
- `delegate_vesting_shares`
- `claim_account`
- `convert`
- `limit_order_create`
- `limit_order_cancel`
- `transfer_to_savings`
- `transfer_from_savings`

**Never sign, always reject**:
- `account_update` (changing keys — only allowed through the emancipation endpoint)
- `account_update2`
- `recover_account`
- Any witness/governance ops

---

## 6. API Routes

All routes are prefixed `/api`. All state-changing routes require CSRF header (`X-CSRF-Token`). Auth is httpOnly session cookie.

### 6.1 Auth — `/api/auth`

#### `POST /api/auth/google`
Verify Google ID token, upsert user, start session.

Request:
```json
{ "credential": "<google-id-token>" }
```

Response (session cookie set):
```json
{
  "user": {
    "id": "...",
    "name": "Meno Bass",
    "picture": "https://...",
    "email": "user@gmail.com",
    "hiveUsername": "menobass",
    "custodyMode": "custodial",
    "isAdmin": false
  }
}
```

If `hiveUsername` is null, user needs to go through account creation or link an existing account.

#### `POST /api/auth/email/register`
Create account with email + password.

Request:
```json
{ "email": "user@example.com", "password": "..." }
```

- Hash password with Argon2id (`argon2.hash(password, { type: argon2.argon2id })`)
- Store `passwordHash`. The raw password is the KDF input for key encryption later.
- Store `emailHash = HMAC-SHA256(KEY_ENCRYPTION_PEPPER, email)` — never store plaintext email.
- `providerId = emailHash`
- Send verification email (optional — see note below)
- Start session.

#### `POST /api/auth/email/login`
```json
{ "email": "user@example.com", "password": "..." }
```
Verify with `argon2.verify(user.passwordHash, password)`. Start session.

#### `GET /api/auth/me`
Returns current session user. Returns 401 if not logged in. Also refreshes CSRF cookie.

```json
{
  "user": {
    "id": "...",
    "name": "...",
    "picture": "...",
    "email": "...",
    "hiveUsername": "menobass",
    "custodyMode": "custodial",
    "isAdmin": false,
    "emancipationRequired": false,
    "accountValueUsd": 3.42
  }
}
```

`emancipationRequired` is `true` when `accountValueUsd >= EMANCIPATION_THRESHOLD_USD` and `custodyMode === 'custodial'`. Frontend should show the emancipation gate when this is true.

#### `POST /api/auth/logout`
Clear session cookie, CSRF cookie.

---

### 6.2 Account Creation — `/api/account`

#### `GET /api/account/eligibility`
Returns whether the current user can create a new Hive account.

```json
{
  "canCreate": true,
  "canLinkExisting": true,
  "reason": null
}
```

Reasons for `canCreate: false`:
- `already_linked` — user already has a Hive account
- `previously_had_account` — `everHadAccount` is true (anti-farming)
- `no_acts` — `@snapie` has no pending claimed accounts

#### `GET /api/account/check-username/:username`
Live username availability. Checks format, on-chain, and in-flight reservations.

```json
{ "available": true, "error": null }
```

#### `POST /api/account/create`
Queue an account creation job. Browser has already generated all four keypairs client-side (see Section 7 for key generation). Only public keys are sent here.

Request:
```json
{
  "username": "newuser",
  "ownerPub": "STM...",
  "activePub": "STM...",
  "postingPub": "STM...",
  "memoPub": "STM...",
  "custodyMode": "custodial" | "emancipated",
  "encryptedKeys": {           // ONLY present if custodyMode === "custodial"
    "owner":   { "iv": "...", "ciphertext": "..." },
    "active":  { "iv": "...", "ciphertext": "..." },
    "posting": { "iv": "...", "ciphertext": "..." },
    "memo":    { "iv": "...", "ciphertext": "..." }
  }
}
```

**IMPORTANT**: For custodial mode, the browser encrypts the private keys BEFORE sending them. The encryption key is derived from the user's password (or a randomly generated one for Google-only users — see Section 8). The server never sees private keys in plaintext.

Validation:
- User is eligible (`eligibility.canCreate === true`)
- Username format valid (3–16 chars, lowercase, letters/digits/hyphens/dots, no consecutive hyphens, each segment ≥ 3 chars starting with letter)
- All four pubkeys are valid Hive public keys
- Four distinct keys (no two roles share a key)
- Job is queued with `status: 'pending'`

Response:
```json
{ "jobId": "uuid" }
```

#### `GET /api/account/job/:jobId`
Poll job status. Only returns jobs belonging to the current user.

```json
{
  "jobId": "...",
  "username": "newuser",
  "status": "confirmed",
  "txId": "abc123",
  "error": null
}
```

Statuses: `pending` | `broadcasting` | `acked` | `confirmed` | `failed` | `expired`

---

### 6.3 Linking an Existing Account — `/api/link`

Some users already have a Hive account. They can link it instead of creating one.

#### `POST /api/link/verify-challenge`
Issue a nonce for the user to sign with their Hive posting key (proves ownership without exposing the key).

Response:
```json
{ "challenge": "snapie-auth:link:1749234567890:randomhex" }
```

#### `POST /api/link/confirm`
```json
{
  "username": "existinguser",
  "challenge": "...",
  "signature": "..."
}
```

- Verify signature against the account's on-chain posting key using `verifyHiveIdentity(username, challenge, signature)` (recycled from butrauth `services/hive.js`)
- Check `hasPostingAuthority(username, SNAPIE_ACCOUNT)` — the account must already have `@snapie` in `posting.account_auths`
- If authority is missing, return `{ error: 'posting_authority_required', instructions: '...' }` with instructions to add it via Keychain
- If OK: set `user.hiveUsername`, `user.custodyMode = 'emancipated'` (they already have their keys), `user.everHadAccount = true`

---

### 6.4 Hive Signing Proxy — `/api/hive`

This is the core of the service. All Hive operations from the frontend come here. Requires valid session.

All endpoints follow the same pattern:
- Validate session + CSRF
- Look up user's `hiveUsername` and `custodyMode`
- Determine op class (posting or active)
- Route to the right signer
- Log to `snapieauth_broadcast_log`
- Return `{ txId }` on success or `{ error, needsClientSigning, unsignedOp }` for emancipated+active

#### `POST /api/hive/broadcast`

General-purpose posting-level endpoint. Accepts the operation array from the frontend.

Request:
```json
{
  "op": ["vote", { "voter": "user", "author": "...", "permlink": "...", "weight": 10000 }]
}
```

- Verify `op[0]` is in the posting-level allowlist (hard-coded — see Section 5)
- If not in allowlist: `403 Forbidden`
- Sign with `SNAPIE_POSTING_KEY` → broadcast via dhive
- Return `{ txId }`

This endpoint serves ALL users regardless of custody mode, because posting-level ops always use @snapie's posting key.

#### `POST /api/hive/transfer`

Active-level op — financial transfer.

Request:
```json
{
  "to": "recipient",
  "amount": "1.000 HIVE",
  "memo": "optional memo"
}
```

Semantic validation:
- `to` must be a valid Hive username format
- `amount` must match `/^\d+\.\d{3} (HIVE|HBD)$/`
- `from` is always the current user's `hiveUsername` (never trust the client for this)
- `memo` max 2048 chars

If `custodyMode === 'custodial'`:
- Decrypt user's active key (see Section 8)
- Build `["transfer", { from, to, amount, memo }]`
- Sign + broadcast
- Return `{ txId }`

If `custodyMode === 'emancipated'`:
- Return `{ needsClientSigning: true, unsignedOp: ["transfer", { from, to, amount, memo }] }`
- Frontend passes this to Keychain/AIOha

#### `POST /api/hive/power-up`

```json
{ "amount": "10.000 HIVE" }
```

Same custodial/emancipated routing. Builds `transfer_to_vesting` op.

#### `POST /api/hive/power-down`

```json
{ "amount": "10.000000 VESTS" }
```

Builds `withdraw_vesting` op.

#### `POST /api/hive/delegate`

```json
{ "delegatee": "username", "amount": "5.000000 VESTS" }
```

Builds `delegate_vesting_shares` op.

#### `POST /api/hive/claim-rewards`

Posting-level op. No active key needed.
Fetches user's pending rewards from chain, builds `claim_reward_balance`, signs with SNAPIE_POSTING_KEY.

---

### 6.5 Emancipation — `/api/emancipate`

#### `GET /api/emancipate/status`

```json
{
  "custodyMode": "custodial",
  "accountValueUsd": 12.50,
  "threshold": 10,
  "forcedEmancipation": true,
  "hiveUsername": "menobass"
}
```

#### `POST /api/emancipate/start`

User-initiated or forced. Requires the user to authenticate their password (to derive the decryption key).

Request (email+password users):
```json
{ "password": "their-password" }
```

Request (Google-only users with custodial keys):
```json
{ "encryptionKey": "hex-string" }
```
(The encryption key for Google-only users was generated in the browser at account creation and shown to the user to save. See Section 8.)

Process:
1. Derive the AES key from the provided password/encryptionKey
2. Decrypt the four private keys from `user.encryptedKeys`
3. Verify decryption was correct (attempt to derive the public keys from the decrypted privkeys and compare against on-chain keys)
4. Return the decrypted private keys to the client — **THIS IS THE ONLY TIME PRIVATE KEYS LEAVE THE SERVER**
5. Set `user.custodyMode = 'emancipated'`
6. Set `user.encryptedKeys = null`
7. Set `user.emancipatedAt = new Date()`

Response:
```json
{
  "keys": {
    "owner":   "5J...",
    "active":  "5K...",
    "posting": "5P...",
    "memo":    "5M..."
  },
  "masterPassword": "P5...",
  "message": "Save these keys now. They will not be shown again. This server has deleted its copy."
}
```

**After emancipation**: The user still has Google login. Social ops still work via @snapie posting authority. Financial ops return `needsClientSigning: true`. The service has no key material for this user.

#### `POST /api/emancipate/confirm`

Client confirms they have saved the keys. Wipes `encryptedKeys` from DB if not already done. Sets `emancipatedAt`.

---

### 6.6 Account Value Check — `/api/account/value`

```json
{
  "hiveUsername": "menobass",
  "hiveBalance": "10.000 HIVE",
  "hbdBalance": "2.500 HBD",
  "vestingShares": "...",
  "hiveValueUsd": 3.50,
  "hbdValueUsd": 2.50,
  "vestingValueUsd": 6.50,
  "totalValueUsd": 12.50,
  "emancipationRequired": true
}
```

This endpoint is hit by the frontend on login to decide if the emancipation gate should be shown. The service also runs this check periodically in the background reconciliation loop.

---

### 6.7 Admin — `/api/admin`

Requires `user.isAdmin === true`.

- `GET /api/admin/stats` — ACT count, pending jobs, user count
- `GET /api/admin/jobs` — list all jobs with status
- `POST /api/admin/claim-act` — trigger a `claim_account` op to replenish ACTs

---

## 7. Client-Side Key Generation (Frontend Responsibility)

The snapie-io frontend generates keys. The server NEVER generates keys and NEVER receives private keys in plaintext. This is non-negotiable.

The frontend uses `@hiveio/dhive`:

```js
import { PrivateKey } from '@hiveio/dhive'

// For a new account:
function generateKeysFromMaster(username, masterPassword) {
  const roles = ['owner', 'active', 'posting', 'memo']
  const keys = {}
  for (const role of roles) {
    const priv = PrivateKey.fromLogin(username, masterPassword, role)
    keys[role] = { private: priv.toString(), public: priv.createPublic().toString() }
  }
  return keys
}

// Master password generation:
function generateMasterPassword() {
  const array = new Uint32Array(10)
  crypto.getRandomValues(array)
  return 'P' + PrivateKey.fromSeed(array.toString()).toString().substring(0, 51)
}
```

The frontend shows the master password to the user **once** and asks them to save it. For custodial users, it also encrypts the private keys before sending them to the server.

---

## 8. Key Encryption (Custodial Mode)

Keys are encrypted in the browser before being sent to the server. The server only ever stores ciphertext.

### For email+password users

The encryption key is derived from the user's password:

```js
// Browser-side (using WebCrypto)
async function deriveEncryptionKey(password, salt) {
  const keyMaterial = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']
  )
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  )
}

async function encryptKey(privateKeyString, aesKey) {
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    aesKey,
    new TextEncoder().encode(privateKeyString)
  )
  return {
    iv: bufToHex(iv),
    ciphertext: bufToHex(ciphertext)
  }
}
```

The server decrypts using the same derived key when the user provides their password on emancipation.

### For Google-only users (no password)

The frontend generates a random 32-byte hex string as the encryption key. This key is shown to the user as their "backup encryption key" and they must save it. The server cannot decrypt without it — this is intentional. The service stores only the ciphertext.

### Server-side decryption (emancipation)

When the user provides their password (or encryption key) to emancipate:

```js
import argon2 from 'argon2'
import crypto from 'crypto'

async function decryptKey(encryptedKey, derivedKeyHex) {
  const key = Buffer.from(derivedKeyHex, 'hex')
  const iv = Buffer.from(encryptedKey.iv, 'hex')
  const ciphertext = Buffer.from(encryptedKey.ciphertext, 'hex')
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv)
  // For AES-GCM, the last 16 bytes of ciphertext are the auth tag
  const authTag = ciphertext.slice(-16)
  const data = ciphertext.slice(0, -16)
  decipher.setAuthTag(authTag)
  return decipher.update(data, null, 'utf8') + decipher.final('utf8')
}
```

The server verifies decryption was correct by re-deriving the public key from the decrypted private key and comparing against what's on-chain.

---

## 9. Account Creation Job Engine

Simplified from butrauth — there are no external providers. The service IS the provider.

### Job Lifecycle

```
pending → broadcasting → acked → confirmed
                ↓
              failed | expired
```

### The reconcile loop (runs every `ACCOUNT_RECONCILE_INTERVAL_MS`)

```js
async function reconcileTick() {
  // 1. Pick up pending jobs and broadcast them
  const pending = await accountJobs().find({ status: 'pending' }).limit(5).toArray()
  for (const job of pending) {
    await broadcastAccountCreate(job)
  }

  // 2. Verify acked jobs on-chain
  const acked = await accountJobs().find({ status: 'acked' }).toArray()
  for (const job of acked) {
    await confirmAckedJob(job)
  }

  // 3. Expire stale jobs
  await accountJobs().updateMany(
    { status: { $in: ['pending', 'broadcasting', 'acked'] }, expiresAt: { $lt: new Date() } },
    { $set: { status: 'expired', failedAt: new Date() }, $unset: { liveUsername: '' } }
  )
}
```

### `broadcastAccountCreate(job)`

```js
async function broadcastAccountCreate(job) {
  await accountJobs().updateOne({ _id: job._id }, { $set: { status: 'broadcasting', attempts: job.attempts + 1 } })

  const op = ['create_claimed_account', {
    creator: process.env.SNAPIE_ACCOUNT,
    new_account_name: job.username,
    owner:   { weight_threshold: 1, account_auths: [], key_auths: [[job.ownerPub, 1]] },
    active:  { weight_threshold: 1, account_auths: [], key_auths: [[job.activePub, 1]] },
    // CRITICAL: Bake @snapie posting authority in at creation — no second transaction needed
    posting: {
      weight_threshold: 1,
      account_auths: [[process.env.SNAPIE_ACCOUNT, 1]],
      key_auths: [[job.postingPub, 1]]
    },
    memo_key: job.memoPub,
    json_metadata: JSON.stringify({ app: 'snapie', created_via: 'snapie-auth' }),
    extensions: []
  }]

  try {
    const result = await hiveClient.broadcast.sendOperations(
      [op], PrivateKey.fromString(process.env.SNAPIE_ACTIVE_KEY)
    )
    await accountJobs().updateOne(
      { _id: job._id },
      { $set: { status: 'acked', txId: result.id, ackAt: new Date() } }
    )
    // Don't wait for full reconcile tick — try to confirm 4s after broadcast
    setTimeout(() => confirmAckedJob(job).catch(() => {}), 4000)
  } catch (err) {
    const reason = hiveErr(err)
    if (job.attempts >= 3) {
      await failJob(job, reason)
    } else {
      await accountJobs().updateOne(
        { _id: job._id },
        { $set: { status: 'pending', lastError: reason } }
      )
    }
  }
}
```

### `confirmAckedJob(job)`

Read account from chain. Verify the account exists with the correct keys. **IMPORTANT**: the posting authority check must accept @snapie in `account_auths` — unlike butrauth's `authorityMatches` which rejects any `account_auths`.

```js
function postingAuthorityMatches(postingAuth, expectedPostingPub, snapieAccount) {
  if (!postingAuth) return false
  const ka = postingAuth.key_auths || []
  const aa = postingAuth.account_auths || []
  // Must have exactly: the user's posting pub + snapie in account_auths
  const hasPostingPub = ka.length === 1 && ka[0][0] === expectedPostingPub && Number(ka[0][1]) >= 1
  const hasSnapie = aa.some(([acc]) => acc === snapieAccount)
  return hasPostingPub && hasSnapie
}

function plainAuthorityMatches(authObj, expectedPub) {
  if (!authObj) return false
  if ((authObj.account_auths || []).length !== 0) return false
  const ka = authObj.key_auths || []
  return ka.length === 1 && ka[0][0] === expectedPub && Number(ka[0][1]) >= 1
}

async function confirmAckedJob(job) {
  const account = await getAccount(job.username)
  if (!account) {
    // Give blocks time to settle — 90s grace period
    if (Date.now() - new Date(job.ackAt).getTime() > 90000) {
      await failJob(job, 'acked_but_account_absent')
    }
    return
  }

  const ok =
    plainAuthorityMatches(account.owner, job.ownerPub) &&
    plainAuthorityMatches(account.active, job.activePub) &&
    postingAuthorityMatches(account.posting, job.postingPub, process.env.SNAPIE_ACCOUNT) &&
    account.memo_key === job.memoPub

  if (!ok) {
    await failJob(job, 'account_keys_mismatch')
    return
  }

  // Delegate RC — mandatory
  await delegateRc(job.username)

  // Confirm the job
  await accountJobs().updateOne(
    { _id: job._id, status: 'acked' },
    {
      $set: { status: 'confirmed', confirmedAt: new Date() },
      $unset: { liveUsername: '' }
    }
  )

  // Link account to user
  await users().updateOne(
    { _id: job.userId },
    {
      $set: {
        hiveUsername: job.username,
        custodyMode: job.custodyMode,
        encryptedKeys: job.custodyMode === 'custodial' ? job.encryptedKeys : null,
        everHadAccount: true,
        updatedAt: new Date()
      }
    }
  )
}
```

### RC Delegation

Immediately after account confirmation. Uses `SNAPIE_POSTING_KEY` (posting key — NOT active key; this is a Hive protocol requirement for `delegate_rc`).

```js
async function delegateRc(username) {
  const op = ['custom_json', {
    required_auths: [],
    required_posting_auths: [process.env.SNAPIE_ACCOUNT],
    id: 'rc',
    json: JSON.stringify(['delegate_rc', {
      from: process.env.SNAPIE_ACCOUNT,
      delegatees: [username],
      max_rc: Math.round(parseFloat(process.env.RC_DELEGATION_BN) * 1e9)
    }])
  }]
  // Retry up to 4 times with backoff
  for (let i = 1; i <= 4; i++) {
    try {
      const r = await hiveClient.broadcast.sendOperations([op], PrivateKey.fromString(process.env.SNAPIE_POSTING_KEY))
      return { ok: true, txId: r.id }
    } catch (e) {
      if (i === 4) return { ok: false, error: e.message }
      await sleep(2000 * i)
    }
  }
}
```

---

## 10. Auth, Session, and CSRF

### Session (httpOnly cookie)

JWT signed with RS256. Cookie name: `snapieauth_session`. HttpOnly, Secure (in production), SameSite=Lax.

JWT payload:
```js
{
  type: 'session',
  userId: '...',
  email: 'user@gmail.com',   // plaintext only in JWT, never in DB
  name: '...',
  picture: '...',
  iat: ...,
  exp: ...
}
```

Reject sessions where `iat < user.sessionMinIat` (allows server-side logout-all).

### CSRF (double-submit cookie)

On every successful login, set a `snapieauth_csrf` cookie (NOT httpOnly, JS-readable, SameSite=Lax). The frontend reads this cookie and echoes it in the `X-CSRF-Token` header on every state-changing request. The server compares header vs cookie.

```js
export function csrfMiddleware(req, res, next) {
  const cookie = req.cookies?.snapieauth_csrf
  const header = req.headers['x-csrf-token']
  if (!cookie || !header || cookie !== header) {
    return res.status(403).json({ error: 'CSRF check failed' })
  }
  next()
}
```

---

## 11. Rate Limiting

Apply these limiters:

| Route group | Window | Max requests |
|---|---|---|
| `/api/auth/*` | 15 min | 30 |
| `/api/account/create` | 1 hour | 5 |
| `/api/account/check-username/*` | 1 min | 40 |
| `/api/hive/broadcast` | 1 min | 60 |
| `/api/hive/transfer` | 1 min | 10 |
| `/api/emancipate/*` | 1 hour | 5 |

---

## 12. Code to Recycle from Butrauth

Located at `/home/meno/Documents/menosoft/butrauth`. These are battle-tested — copy, strip what you don't need, adapt imports.

| butrauth file | What to take |
|---|---|
| `backend/src/services/hive.js` | Copy whole file — `getAccount`, `verifyHiveIdentity`, `hasPostingAuthority`, `broadcastOps`, `verifySignature`. Update `NODES_MAINNET`. |
| `backend/src/routes/auth.js` | Take `verifyGoogleToken()` and the `POST /google` handler pattern. Strip PIN, GitHub, Discord. |
| `backend/src/services/users.js` | Take `upsertUser`, `startSession`, `shapeUser` patterns. Adapt schema to snapie-auth. |
| `backend/src/services/auth.js` | Take JWT signing/verification, session cookie helpers, `authMiddleware`. |
| `backend/src/services/csrf.js` | Copy whole file. |
| `backend/src/services/async-middleware.js` | Copy whole file (it's 3 lines). |
| `backend/src/services/auth-events.js` | Optional — take if you want an audit log collection. |
| `backend/src/services/account-jobs.js` | Take the reconcile loop structure, `failJob`, `requeueOrFail` patterns. Replace `authorityMatches` with the new posting-aware version (Section 9). Remove all provider federation code. |
| `account-provider/src/index.js` | Take `delegateRc`, `hiveErr`, the `broadcastAccountCreate` pattern. |
| `backend/src/db/init.js` | Take the `ensureIndexes` pattern. Adapt for snapie-auth collections. |

---

## 13. What snapie-io (the Frontend) Needs

The Snapie Next.js app at `/home/meno/Documents/menosoft/snapieio/snapie-io` is the primary consumer. Here is what it needs from this service:

### Authentication flow

1. User clicks "Sign in with Google" → Google One Tap fires → sends `credential` to `POST /api/auth/google`
2. Session cookie is set → frontend calls `GET /api/auth/me` → gets user object
3. If `hiveUsername` is null → show account creation or link flow
4. If `emancipationRequired: true` → show emancipation gate before anything else

### For all Hive social operations

Instead of calling AIOha/Keychain directly for logged-in-via-Google users, the frontend calls `POST /api/hive/broadcast` with the operation. The service signs it with @snapie's posting key.

For users logged in with Keychain/HiveSigner (existing Hive users who linked an account), the frontend continues to use AIOha directly — it only proxies through snapie-auth for Google/email-authenticated sessions.

The frontend should check `GET /api/auth/me` → `custodyMode` to decide:
- `custodyMode === 'custodial'` OR `custodyMode === 'emancipated'` with posting op → call snapie-auth
- `custodyMode === 'emancipated'` with active op → call `GET /api/hive/unsigned/:opType` then pass to AIOha/Keychain

### CORS

snapie-auth must allow requests from `FRONTEND_URL`. The Next.js app sends credentials (cookies) on all requests to this service, so `credentials: true` and exact origin match (no wildcard) is required.

### The snapie-auth client SDK (build this in snapie-io)

Create `lib/snapie-auth/client.ts` in the Next.js project:

```ts
// All requests go through this — handles CSRF, credentials, base URL.
const BASE = process.env.NEXT_PUBLIC_SNAPIE_AUTH_URL // e.g. https://auth.snapie.io

async function api(method: string, path: string, body?: unknown) {
  const csrf = getCookie('snapieauth_csrf')
  const res = await fetch(`${BASE}${path}`, {
    method,
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      ...(csrf ? { 'X-CSRF-Token': csrf } : {})
    },
    body: body ? JSON.stringify(body) : undefined
  })
  if (!res.ok) throw new Error((await res.json()).error || `HTTP ${res.status}`)
  return res.json()
}

export const snapieAuth = {
  me: () => api('GET', '/api/auth/me'),
  loginGoogle: (credential: string) => api('POST', '/api/auth/google', { credential }),
  logout: () => api('POST', '/api/auth/logout'),
  broadcast: (op: [string, Record<string, unknown>]) => api('POST', '/api/hive/broadcast', { op }),
  transfer: (to: string, amount: string, memo: string) => api('POST', '/api/hive/transfer', { to, amount, memo }),
  claimRewards: () => api('POST', '/api/hive/claim-rewards'),
  createAccount: (payload: CreateAccountPayload) => api('POST', '/api/account/create', payload),
  jobStatus: (jobId: string) => api('GET', `/api/account/job/${jobId}`),
  emancipate: (password: string) => api('POST', '/api/emancipate/start', { password }),
}
```

---

## 14. Deployment

### Directory structure

```
snapie-auth/
├── src/
│   ├── index.js              # Express app entry
│   ├── db/
│   │   └── init.js           # ensureIndexes
│   ├── routes/
│   │   ├── auth.js           # Google + email login, /me, logout
│   │   ├── account.js        # create, eligibility, check-username, job status
│   │   ├── link.js           # link existing Hive account
│   │   ├── hive.js           # signing proxy
│   │   ├── emancipate.js     # emancipation flow
│   │   └── admin.js          # admin endpoints
│   └── services/
│       ├── hive.js           # dhive wrapper
│       ├── auth.js           # JWT, session cookie
│       ├── csrf.js           # CSRF middleware
│       ├── users.js          # upsert, session start
│       ├── account-jobs.js   # job engine + reconcile loop
│       ├── account-value.js  # HIVE price feed, account value calc
│       ├── key-crypto.js     # AES-256-GCM encrypt/decrypt
│       ├── db.js             # MongoDB connection
│       └── async-middleware.js
├── keys/
│   ├── jwt-private.pem
│   └── jwt-public.pem
├── .env
├── .env.example
└── package.json
```

### `package.json`

```json
{
  "name": "snapie-auth",
  "version": "1.0.0",
  "type": "module",
  "scripts": {
    "start": "node src/index.js",
    "dev": "node --watch src/index.js"
  },
  "dependencies": {
    "@hiveio/dhive": "^1.3.1",
    "argon2": "^0.31.2",
    "cookie-parser": "^1.4.6",
    "cors": "^2.8.5",
    "express": "^4.18.2",
    "express-rate-limit": "^7.1.5",
    "helmet": "^7.1.0",
    "jsonwebtoken": "^9.0.2",
    "mongodb": "^6.3.0"
  }
}
```

### VPS setup

Run with PM2:
```bash
npm install -g pm2
pm2 start src/index.js --name snapie-auth --interpreter node
pm2 save
pm2 startup
```

Or use the provided `docker-compose.yml` (to be created alongside this service).

Nginx reverse proxy on port 443 → forward to `localhost:3500`.

---

## 15. Security Notes

1. **Private keys never in plaintext on the server** — the server receives only encrypted blobs. Decryption happens only at emancipation, and the plaintext is returned immediately and never stored.

2. **Email never stored in plain text** — only `HMAC-SHA256(pepper, email)`. Plaintext email lives only in the session JWT.

3. **Posting key operations only** — the service refuses to sign non-posting ops via the general `/api/hive/broadcast` endpoint. Financial ops are only available on named semantic endpoints with explicit validation.

4. **Verify posting authority before signing custodial active-key ops** — before signing a transfer for a custodial user, check on-chain that the account is still theirs (the session + hiveUsername match in DB is sufficient).

5. **Always set `from` from the session** — never trust the client to tell you who is sending a transfer.

6. **Never store `SNAPIE_ACTIVE_KEY` in the DB** — it lives only in the environment. Same for `SNAPIE_POSTING_KEY`.

7. **CORS must be exact-origin** — `credentials: true` requires a matching origin, not `*`.

8. **RC delegation after every account creation** — without it the new account has ~0 RC and cannot do anything on-chain. This must not be skipped.

---

## 16. Out of Scope (for now)

- Email verification (can add later — for now email+password users are trusted at registration)
- Paid account creation (fiat/Stripe) — the service is built to support it but the payment flow is a future concern
- Key rotation (changing user's Hive keys while in custodial mode)
- Multi-device session management
- Mobile app support (the API is stateless enough for it, just add cookie alternatives)
