# PHP2Shell — ownership-verified passive posture checker (backend)

A deployment-agnostic Node.js service that lets a user scan a domain **only after
proving they own it**, then runs a **strictly passive** PHP-version posture check.

- **Authorization gate** — two ownership challenges:
  - **Email**: a one-time link sent to an address *on the domain* (`admin@`, `security@`,
    `webmaster@`, `postmaster@`, `hostmaster@`, or any address whose host equals the domain).
  - **DNS TXT**: a random, per-domain record `_php2shell-verify.<domain>` the owner publishes.
- **Passive scan only** — after verification, the server makes **one headers-only request**
  to the verified host and infers the PHP version from the `Server` / `X-Powered-By` banners.
  It **never** sends a payload, never tries to trigger CVE-2026-109618 / CVE-2026-109619, and
  labels every result as *inference, not proof*.

This backend is the engine; the static hub (`../index.html`, plus the `scan.html` verification
page) is the UI that drives it.

## Why a backend at all?

A browser (and a published artifact) cannot send email, resolve DNS, or fetch arbitrary hosts.
Those three things are exactly what ownership verification and the posture check require, so they
must run server-side — which makes **SSRF the #1 risk** and the main thing this code defends against.

## Security properties

- **SSRF guard (fail-closed):** every resolved A/AAAA address must be public global-unicast or the
  whole scan is refused. Blocks loopback, private, link-local (incl. `169.254.169.254` cloud
  metadata), unique-local, CGNAT, IPv4-mapped/6to4/NAT64 embeddings, reserved and multicast —
  for both IPv4 and IPv6 (`src/lib/ssrfGuard.js`, tested in `test/ssrfGuard.test.js`).
- **Anti-DNS-rebinding:** resolve once, validate, then **pin** the connection to that exact IP
  (`lookup` override); the kernel never re-resolves (`src/lib/safeFetch.js`).
- **No cross-host redirects, https-only** (http only if `HUB_ALLOW_HTTP=true`), headers-only,
  strict timeouts and size caps.
- **Target host comes from the grant, never the request body** — a scan can only ever hit the
  exact verified host.
- **Tokens:** CSPRNG, ≥128-bit, split-token (`selector.verifier`), only hashes stored, constant-time
  compare, single-use, short-TTL. Ownership → a separate short-lived, use-capped, revocable **grant**.
- **Rate limits** per IP / domain / recipient, SQLite-backed. **No raw IPs or secrets at rest**
  (IPs are HMAC'd; audit log is hash-only).

## Requirements

- Node.js ≥ 20
- `npm install` (native build for `better-sqlite3`)

## Configure

```bash
cp .env.example .env
# then edit .env
node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))"  # -> IP_HASH_KEY
```

Required: `PUBLIC_BASE_URL`, `HUB_URL`, `IP_HASH_KEY`. See `.env.example` for all options.

### Email via Resend (recommended)

1. In the [Resend dashboard](https://resend.com): add and **verify your sending domain** (add the
   DNS records Resend gives you), then **create an API key**.
2. Put the key in `RESEND_API_KEY` (in your host's env/secrets — never commit it).
3. Set `MAIL_FROM` to an address on the domain you verified in Resend, e.g.
   `MAIL_FROM="PHP2Shell Verify <verify@yourdomain.com>"`.

If `RESEND_API_KEY` is empty the server falls back to SMTP (`SMTP_*`); if neither is set, the email
challenge is disabled and the **DNS-TXT challenge still works** (and is the recommended default — it
sends no mail).

## Run

```bash
npm install
npm test          # unit tests (SSRF classifier + version inference)
npm start         # starts the API on $PORT (default 8080)
```

Deploy anywhere that runs a long-lived Node process (a VM, a container, Fly.io, Render, Railway,
a systemd unit behind nginx/Caddy). Put it behind a TLS-terminating reverse proxy. For defense in
depth, run the scanner's egress through a locked-down network path (egress firewall, IMDSv2 enforced,
IPv6 disabled if unused).

## Wire the hub to it

Serve `scan.html` with a global `window.P2S_API_BASE = "https://api.yourdomain.com"` (same-origin is
simplest: set `SERVE_STATIC=true` to have this process serve the hub too). The page calls the API
below; it never does email/DNS/network itself.

## API

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/verify/email/start` | Begin email challenge; send the one-time link. |
| GET  | `/api/verify/email/confirm?token=` | Email link target; verifies and redirects to the hub. |
| POST | `/api/verify/dns/start` | Begin DNS TXT challenge; returns the record to publish. |
| POST | `/api/verify/dns/check` | Resolve the TXT record and verify. |
| GET  | `/api/verify/:id/status?claimSecret=` | Poll challenge progress (bound to the originating session). |
| POST | `/api/verify/:id/claim` | Exchange a verified challenge for one scan **grant**. |
| POST | `/api/scan` | `Authorization: Bearer <grant>` → run the passive posture check. |
| GET  | `/api/scan/:id` | Fetch a stored result (same grant). |
| GET  | `/api/version-table` | Patched/EOL table + disclaimer (keeps the hub in sync). |
| GET  | `/api/healthz` | Liveness probe. |

## What this service deliberately does not do

No exploitation, ever. No “scan any URL” / anonymous path. No general-purpose fetch/proxy. No port
scanning, path crawling, or probing secondary services. No following redirects to non-public IPs,
non-http(s) schemes, or cross-host targets. No storing response bodies. No disabling TLS verification,
SSRF guards, or rate limits via any flag. Ownership verification is the only authorization gate.
