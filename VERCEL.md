# Deploying PHP2Shell on Vercel

This repo deploys to Vercel as a **static hub** (`index.html`, `scan.html`) plus a **serverless
API** (`/api/*`, one Express function) backed by **Upstash Redis**.

The security-critical logic (SSRF guard, IP-pinned fetch, tokens, domain rules, version
inference) is imported unchanged from `server/src/**`, so the Vercel and Node builds never diverge.
Short-TTL data (verifications, grants, results, rate-limit counters) lives in Redis with native
expiry — no background sweep needed.

## One-time setup (≈3 minutes)

### 1. Create the project
Import `lbd226/php2shell` into Vercel (Add New → Project → pick the repo). Framework preset:
**Other**. Root directory: repo root. No build command needed (static + functions).

### 2. Add Upstash Redis (storage)
In the project: **Storage → Create / Connect Store → Upstash (Redis)**. Connecting it injects
`UPSTASH_REDIS_REST_URL` and `UPSTASH_REDIS_REST_TOKEN` into the project automatically.

### 3. Add Resend (email challenge)
In the [Resend dashboard](https://resend.com): verify your sending domain and create an API key.
Then in Vercel **Settings → Environment Variables** add:
- `RESEND_API_KEY` = your key (secret)
- `MAIL_FROM` = e.g. `PHP2Shell Verify <verify@yourdomain.com>` (a domain verified in Resend)

(Leave both empty to disable email — the DNS-TXT challenge still works.)

### 4. Set the base URLs + secret
In **Settings → Environment Variables** add:
- `IP_HASH_KEY` = 32+ random bytes — `node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))"`
- `PUBLIC_BASE_URL` = your deployment origin, e.g. `https://php2shell.vercel.app` (or your custom domain)
- `HUB_URL` = same origin as `PUBLIC_BASE_URL`

Redeploy after setting env vars.

## Verify

- `GET /api/healthz` → `{ "ok": true, ... }`
- `GET /api/version-table` → the patched/EOL table
- Open `/scan.html`, verify a domain you own via DNS TXT, and run the passive check.

## Notes

- `vercel.json` routes `/api/:path*` to the single function and sets `maxDuration: 30`
  (lower it to ≤10 on the Hobby plan; a slow scan may otherwise be cut off).
- `index.html` and `scan.html` are served statically from the same origin as `/api`, so the
  page calls the API same-origin (no `window.P2S_API_BASE` needed).
- The `server/` directory is the standalone Node (SQLite) build for non-serverless hosts; Vercel
  ignores its `node_modules`/DB via `.vercelignore` and never bundles `better-sqlite3`.
