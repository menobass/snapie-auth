# snapie-auth

Hive account gateway and signing proxy for [Snapie](https://snapie.io).

- Google OAuth and email/password authentication
- Custodial Hive account creation using pre-claimed account tokens (ACTs)
- Server-side key custody — no wallet required for new users
- Posting-level and active-level signing proxy
- Voluntary key export (emancipation)
- Sponsor token system for gifting free accounts
- Internal API for service-to-service account provisioning
- Frontend UI at `/` with API docs at `/docs.html`

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

### systemd service

```ini
[Unit]
Description=snapie-auth
After=network.target mongod.service

[Service]
User=meno
WorkingDirectory=/home/meno/snapie-auth
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
| `INTERNAL_API_KEY` | Bearer token for `/api/internal/*` endpoints |

Generate secrets:
```bash
openssl rand -hex 32   # KEY_ENCRYPTION_PEPPER
openssl rand -hex 32   # INTERNAL_API_KEY
```

---

## API

Full reference at `/docs.html` or `public/docs.html`.  
Machine-readable contract at `/llms.txt`.

### Auth
| Method | Path | Description |
|---|---|---|
| POST | `/api/auth/google` | Google sign-in |
| POST | `/api/auth/email/register` | Email registration |
| POST | `/api/auth/email/login` | Email login |
| GET | `/api/auth/me` | Current session |
| POST | `/api/auth/logout` | Clear cookies |

### Account
| Method | Path | Description |
|---|---|---|
| GET | `/api/account/eligibility` | Check if user can create a free account |
| GET | `/api/account/check-username/:u` | Username availability |
| POST | `/api/account/create` | Create Hive account |
| GET | `/api/account/job/:jobId` | Poll creation status |

### Hive signing proxy
| Method | Path | Auth level |
|---|---|---|
| POST | `/api/hive/broadcast` | Posting (custodial: signed; emancipated: unsigned op returned) |
| POST | `/api/hive/transfer` | Active |
| POST | `/api/hive/power-up` | Active |
| POST | `/api/hive/power-down` | Active |
| POST | `/api/hive/delegate` | Active |

### Internal (Bearer token)
| Method | Path | Description |
|---|---|---|
| POST | `/api/internal/provision-account` | Create account without user session |
| GET | `/api/internal/jobs/:jobId` | Poll + retrieve keys (one-shot) |
| POST | `/api/internal/issue-sponsor-token` | Gift a free account to an email |

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

Custodial users can export their private keys at any time via `POST /api/emancipate/start`. Snapie deletes its copy immediately. Once emancipated:

- Posting-level ops (vote, comment, custom_json) are still proxied via Snapie's posting authority
- Active-level ops (transfer, power-up) return an unsigned op for the user to sign with their own wallet (Keychain, etc.)

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
- Custodial keys are encrypted with `AES-256-GCM` using a key derived from `HMAC-SHA256(pepper, userId)` — no password from the user, no stored key material
- All state-mutating API calls require a CSRF double-submit token
- `KEY_ENCRYPTION_PEPPER` must never change after first deploy — doing so makes all custodial keys unrecoverable
- The `INTERNAL_API_KEY` is compared with `crypto.timingSafeEqual` to prevent timing attacks
