# snapie-auth

Hive account gateway and signing proxy for [Snapie](https://snapie.io).

- Google OAuth and email/password authentication
- Custodial Hive account creation using pre-claimed account tokens (ACTs)
- Server-side key custody — no wallet required for new users
- Posting-level and active-level signing proxy
- Voluntary key export (emancipation)
- Sponsor token system for gifting free accounts (email invites, even pre-registration)
- Daily free-account quota with public `/api/quota` endpoint for consuming apps
- HIVE + Bitcoin Lightning (v4v.app) payments for paid account creation — no KYC
- Account creation fee derived live from top-20 witness median — not hardcoded
- Admin panel at `/admin.html` — sponsorships, admin management, system controls
- Internal API for service-to-service account provisioning
- Frontend UI at `/` with API docs at `/docs.html`
- Support: [Discord](https://discord.gg/CgJP7t7nWy)

---

## Prerequisites

- Node.js 20+
- MongoDB 6+
- A Hive account with posting and active keys (the `@snapie` service account)
- A Google Cloud project with OAuth 2.0 credentials

---

## Setup

### 1. Clone and install

```bash
git clone https://github.com/your-org/snapie-auth.git
cd snapie-auth
npm install
```

### 2. Generate JWT keypair

```bash
bash scripts/gen-keys.sh
```

This writes `keys/jwt-private.pem` and `keys/jwt-public.pem`. The `keys/` directory is gitignored — back these up separately. Rotating them invalidates all active sessions.

### 3. Configure environment

```bash
cp .env.example .env
```

Fill in all values — see [Environment Variables](#environment-variables) below.

### 4. Google OAuth setup

1. Go to [console.cloud.google.com](https://console.cloud.google.com) → create a project
2. **APIs & Services → OAuth consent screen**
   - User type: External
   - App name: Snapie
   - Authorized domain: `snapie.io`
   - Scopes: `email`, `profile`, `openid`
   - Publish the app (otherwise limited to 100 test users)
3. **APIs & Services → Credentials → Create → OAuth 2.0 Client ID**
   - Type: Web application
   - Authorized JavaScript origins: `https://auth.snapie.io`
   - Authorized redirect URIs: `https://auth.snapie.io/manage.html`
4. Copy the **Client ID** → `GOOGLE_CLIENT_ID` in `.env`

No client secret is needed — verification uses Google's `tokeninfo` endpoint.

### 5. Run

```bash
# Development (auto-restart on file change)
npm run dev

# Production
npm start
```

---

## Deployment (VPS + nginx)

### nginx config

```nginx
server {
    listen 443 ssl;
    server_name auth.snapie.io;

    ssl_certificate     /etc/letsencrypt/live/auth.snapie.io/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/auth.snapie.io/privkey.pem;

    location / {
        proxy_pass         http://127.0.0.1:3500;
        proxy_http_version 1.1;
        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
    }
}
```

### PM2 (recommended)

```bash
pm2 start src/index.js --name snapie-auth
pm2 save
pm2 startup   # follow the printed command to enable on boot
```

Logs: `pm2 logs snapie-auth`  
Restart: `pm2 restart snapie-auth`

### systemd service (alternative)

```ini
[Unit]
Description=snapie-auth
After=network.target mongod.service

[Service]
User=meno
WorkingDirectory=/var/www/snapie-auth
ExecStart=/usr/bin/node src/index.js
Restart=always
RestartSec=5
Environment=NODE_ENV=production

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now snapie-auth
sudo journalctl -u snapie-auth -f
```

---

## Environment Variables

See `.env.example` for the full list. Key variables:

| Variable | Description |
|---|---|
| `PORT` | Port to listen on (default: 3500) |
| `FRONTEND_URL` | Comma-separated allowed CORS origins |
| `MONGODB_URI` | Full MongoDB connection string |
| `JWT_PRIVATE_KEY_PATH` | Path to RS256 private key (default: `./keys/jwt-private.pem`) |
| `JWT_PUBLIC_KEY_PATH` | Path to RS256 public key (default: `./keys/jwt-public.pem`) |
| `GOOGLE_CLIENT_ID` | Google OAuth client ID |
| `SNAPIE_ACCOUNT` | Hive service account username (e.g. `snapie`) |
| `SNAPIE_ACTIVE_KEY` | Active private key for `create_claimed_account` |
| `SNAPIE_POSTING_KEY` | Posting private key for signing proxy + RC delegation |
| `KEY_ENCRYPTION_PEPPER` | 32-byte hex secret for custodial key encryption — **never change after first deploy** |
| `EMANCIPATION_THRESHOLD_USD` | Force key export above this account value (0 to disable) |
| `RC_DELEGATION_BN` | RC delegated to new accounts in billions (default: 5) |
| `FREE_ACCOUNTS_PER_IP_PER_DAY` | Max free account creations per IP per day (default: 2) |
| `FREE_ACCOUNTS_GLOBAL_PER_DAY` | Max free account creations globally per day (default: 10) |
| `SNAPIE_RECEIVING_ACCOUNT` | Hive account that receives HIVE/Lightning payments |
| `SNAPIE_LIGHTNING_HIVE_ACCOUNT` | Hive account registered with v4v.app (defaults to `SNAPIE_RECEIVING_ACCOUNT`) |
| `ACCOUNT_FEE_CACHE_MS` | How long to cache the witness account creation fee (default: 600000 = 10 min) |
| `V4V_RECEIVE_CURRENCY` | Currency v4v.app converts Lightning to: `hive` or `hbd` (default: `hive`) |
| `EMAIL_HOST` | SMTP host (e.g. `smtp.resend.com`) |
| `EMAIL_PORT` | SMTP port (default: 465) |
| `EMAIL_SECURE` | Use TLS (default: true) |
| `EMAIL_USER` | SMTP username |
| `EMAIL_PASS` | SMTP password / API key |
| `EMAIL_FROM` | From address for outbound email |
| `AUTH_BASE_URL` | Public base URL, used in email links (e.g. `https://auth.snapie.io`) |
| `ADMIN_EMAILS` | Comma-separated emails auto-granted admin on login (bootstrap — see [Admin](#admin)) |
| `INTERNAL_API_KEY` | Bearer token for `/api/internal/*` endpoints |
| `LICENSE_REDIRECT_HOSTS` | Comma-separated hostnames allowed as the `/login` redirect target for plugin licensing (default: `licensing.menosoft.xyz`) |

Generate secrets:
```bash
openssl rand -hex 32   # KEY_ENCRYPTION_PEPPER
openssl rand -hex 32   # INTERNAL_API_KEY
```

---

## API

Full reference at `/docs.html` or `public/docs.html`.  
Machine-readable contract at `/llms.txt`.

### Public
| Method | Path | Description |
|---|---|---|
| GET | `/api/quota` | Free account slots remaining today — no auth required |
| GET | `/api/public-config` | Frontend config (Google client ID, network) |

### Auth
| Method | Path | Description |
|---|---|---|
| POST | `/api/auth/google` | Google sign-in |
| POST | `/api/auth/email/register` | Email registration — sends verification email, returns 202 |
| POST | `/api/auth/email/login` | Email login |
| POST | `/api/auth/email/resend` | Resend verification email |
| GET  | `/api/auth/email/verify` | Email verification link handler (redirects to /manage.html) |
| GET  | `/api/auth/me` | Current session |
| POST | `/api/auth/logout` | Clear cookies |

### Payments (no KYC)
| Method | Path | Description |
|---|---|---|
| GET  | `/api/payment/fee` | Live account creation fee from witness median + USD equivalent |
| POST | `/api/payment/hive-intent` | Create a HIVE payment intent — returns memo + receiving account |
| POST | `/api/payment/lightning-intent` | Create a Bitcoin Lightning invoice via v4v.app |
| GET  | `/api/payment/intent/:memo` | Poll intent status (`pending` / `confirmed` / `expired`) |

On confirmation, the user can call `POST /api/account/create` — the paid flag bypasses the daily free quota. Both intent endpoints return `409 already_linked` if the user already has a Hive account (one account per identity is enforced).

### Account
| Method | Path | Description |
|---|---|---|
| GET  | `/api/account/eligibility` | Check if user can create a free account |
| GET  | `/api/account/check-username/:u` | Username availability |
| POST | `/api/account/create` | Create Hive account |
| GET  | `/api/account/job/:jobId` | Poll creation status |
| GET  | `/api/account/value` | Account balance and USD value; includes `emancipationRequired` |

### Link existing account
| Method | Path | Description |
|---|---|---|
| POST | `/api/link/verify-challenge` | Issue a challenge nonce; returns `{ challenge, snapieAccount }` |
| POST | `/api/link/confirm` | Confirm link with signed challenge + username |

### Hive signing proxy
| Method | Path | Description |
|---|---|---|
| POST | `/api/hive/sign-message` | Sign a challenge with posting key — custodial: server signs; emancipated: returns `{ needsClientSigning, message, account, keyType }` |
| POST | `/api/hive/broadcast` | Posting-level ops (vote, comment, custom_json, etc.) — always proxied for all users |
| POST | `/api/hive/transfer` | Transfer HIVE or HBD |
| POST | `/api/hive/transfer-to-savings` | Move funds to savings |
| POST | `/api/hive/transfer-from-savings` | Withdraw from savings (3-day delay) |
| POST | `/api/hive/power-up` | Stake HIVE as Hive Power |
| POST | `/api/hive/power-down` | Begin 13-week unstaking |
| POST | `/api/hive/delegate` | Delegate Hive Power (set to 0 to remove) |
| POST | `/api/hive/convert` | Convert HBD → HIVE (~3.5 days, median price) |
| POST | `/api/hive/collateralized-convert` | Convert HIVE → HBD instantly |
| POST | `/api/hive/limit-order-create` | Place a limit or market order on the internal HIVE/HBD market |
| POST | `/api/hive/limit-order-cancel` | Cancel an open limit order |
| POST | `/api/hive/claim-rewards` | Claim pending reward balances |

Active-level ops (everything except `broadcast`, `claim-rewards`, and `sign-message`) return:
- **Custodial**: `{ txId }` — signed and broadcast by the server
- **Emancipated**: `{ needsClientSigning: true, unsignedOp, account, keyType: "active" }` — hand off to Aioha or Keychain

### Admin (session, `isAdmin` required)
| Method | Path | Description |
|---|---|---|
| GET | `/api/admin/stats` | ACT count, pending jobs, user count |
| GET | `/api/admin/jobs` | Last 100 account creation jobs |
| POST | `/api/admin/claim-act` | Claim one ACT from the Snapie account |
| GET | `/api/admin/sponsor-tokens` | List all sponsor tokens |
| POST | `/api/admin/sponsor-tokens` | Issue token — optionally send invite email |
| DELETE | `/api/admin/sponsor-tokens/:id` | Revoke an unused token |
| GET | `/api/admin/admins` | List admin users |
| POST | `/api/admin/admins` | Grant admin by email |
| DELETE | `/api/admin/admins/:userId` | Revoke admin |

### Internal (Bearer token)
| Method | Path | Description |
|---|---|---|
| POST | `/api/internal/provision-account` | Create account without user session |
| GET | `/api/internal/jobs/:jobId` | Poll + retrieve keys (one-shot) |
| POST | `/api/internal/issue-sponsor-token` | Gift a free account to an email |

---

## Admin

The admin panel is at `/admin.html`. Access requires `isAdmin: true` on the user's account.

### Bootstrap (first admin)

Add your email to `ADMIN_EMAILS` in `.env` and restart the process. On your next login, `isAdmin` is permanently granted to your account in the DB. Once you're in, you can grant others via the Admins tab — the env var is only needed for the initial bootstrap.

```
ADMIN_EMAILS=you@example.com,colleague@example.com
```

### Features
- **Sponsorships tab** — issue invite tokens to any email (registered or not), optionally send an invite email, view/revoke pending invites, see used invites
- **Admins tab** — grant or revoke admin access by email
- **System tab** — claim ACTs, view recent account creation jobs

---

## Sponsor Tokens

External apps can earn their users a free Hive account via the Internal API:

```bash
curl -X POST https://auth.snapie.io/api/internal/issue-sponsor-token \
  -H "Authorization: Bearer $INTERNAL_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"email": "alice@example.com", "note": "earned 500 credits", "expiresInDays": 30}'
```

When Alice registers with that email and creates an account, the token is consumed automatically — her account uses one of Snapie's ACTs at no cost to her.

---

## Emancipation

Custodial users can export their private keys — and the master password those keys derive from — at any time via `POST /api/emancipate/start`. Snapie deletes its copy immediately. The master password can be imported into any Hive wallet (Keychain, PeakD) to regenerate all four keys. (`masterPassword` is `null` for accounts created before master-password support; their four keys are still returned.) Once emancipated:

- Posting-level ops (vote, comment, custom_json) are still proxied via Snapie's posting authority
- Active-level ops (transfer, power-up, etc.) return `{ needsClientSigning: true, unsignedOp, account, keyType: "active" }` for the consuming app to hand off to Aioha or Keychain

If `EMANCIPATION_THRESHOLD_USD` is set, users whose account value exceeds the threshold are blocked from posting until they emancipate.

---

## Account Creation Flow

```
POST /api/account/create → { jobId }
  ↓
GET /api/account/job/:jobId   (poll every 3–5s)
  pending → broadcasting → acked → confirmed
                                      ↓
                              user.hiveUsername set
```

The reconcile loop runs every `ACCOUNT_RECONCILE_INTERVAL_MS` ms (default 5000). It broadcasts pending jobs, confirms acked transactions on-chain, and delegates RC to new accounts.

---

## Security Notes

- Email addresses are never stored in plaintext — only `HMAC-SHA256(pepper, email)`
- Custodial keys are derived from a per-account master password via Hive's `fromLogin`, then encrypted with `AES-256-GCM` using a key derived from `HMAC-SHA256(pepper, userId)` — no password from the user, no stored key material. The master password is encrypted and stored the same way, and returned alongside the keys on emancipation
- All state-mutating API calls require a CSRF double-submit token
- `KEY_ENCRYPTION_PEPPER` must never change after first deploy — doing so makes all custodial keys unrecoverable
- The `INTERNAL_API_KEY` is compared with `crypto.timingSafeEqual` to prevent timing attacks
