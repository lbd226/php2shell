import { Router } from 'express';
import { z } from 'zod';
import { config } from '../config.js';
import { normalizeDomain, emailHostMatchesDomain, DomainError } from '../lib/domain.js';
import { RFC2142_MAILBOXES } from '../constants.js';
import { hashIp } from '../lib/tokens.js';
import { enforce } from '../lib/rateLimit.js';
import { audit } from '../lib/audit.js';
import { emailEnabled } from '../lib/mailer.js';
import * as emailChallenge from '../services/emailChallenge.js';
import * as dnsChallenge from '../services/dnsChallenge.js';
import * as verifications from '../services/verificationService.js';

const r = Router();
const MIN = 60_000;

const ipHashOf = (req) => hashIp(req.ip);

// ---- Email challenge ----
const emailStartSchema = z.object({
  domain: z.string().min(1).max(253),
  email: z.string().max(254).optional(),
  localpart: z.enum(RFC2142_MAILBOXES).optional(),
});

r.post('/email/start', async (req, res, next) => {
  try {
    if (!emailEnabled) {
      return res.status(503).json({ error: 'email_disabled', message: 'שער המייל אינו מוגדר; השתמשו באתגר DNS TXT' });
    }
    const body = emailStartSchema.parse(req.body);
    const domain = normalizeDomain(body.domain);

    let recipient;
    if (body.email) {
      if (!emailHostMatchesDomain(body.email, domain)) {
        throw new DomainError('כתובת המייל חייבת להיות על אותו דומיין בדיוק שאתם מאמתים');
      }
      recipient = body.email.trim();
    } else {
      recipient = `${body.localpart || 'admin'}@${domain}`;
    }

    const ipHash = ipHashOf(req);
    enforce(`ip:${ipHash}:verifystart`, 10, 10 * MIN);
    enforce(`domain:${domain}:email`, 5, 60 * MIN);
    enforce(`rcpt:${recipient}:email`, 3, 60 * MIN);

    const out = await emailChallenge.startAndSend({ domain, emailAddress: recipient, ipHash });
    audit('email_sent', { verificationId: out.verificationId, domain, ipHash, outcome: 'sent' });
    res.status(202).json(out);
  } catch (e) { next(e); }
});

r.get('/email/confirm', (req, res) => {
  const token = typeof req.query.token === 'string' ? req.query.token : '';
  const out = emailChallenge.confirm(token);
  if (out.ok) {
    audit('confirm', { verificationId: out.id, domain: out.domain, outcome: 'verified' });
    // Redirect to the hub, with the one-time token stripped from the URL.
    return res.redirect(302, `${config.HUB_URL}/scan.html#verified=1&id=${encodeURIComponent(out.id)}`);
  }
  const statusMap = { expired: 410, used: 410, locked: 429, invalid: 400 };
  res.status(statusMap[out.reason] || 400).type('html; charset=utf-8').send(confirmErrorPage(out.reason));
});

// ---- DNS TXT challenge ----
r.post('/dns/start', (req, res, next) => {
  try {
    const { domain: raw } = z.object({ domain: z.string().min(1).max(253) }).parse(req.body);
    const domain = normalizeDomain(raw);
    const ipHash = ipHashOf(req);
    enforce(`ip:${ipHash}:verifystart`, 10, 10 * MIN);
    enforce(`domain:${domain}:dnsstart`, 10, 60 * MIN);
    const out = dnsChallenge.start({ domain, ipHash });
    audit('verify_start', { verificationId: out.verificationId, domain, ipHash, outcome: 'dns' });
    res.json(out);
  } catch (e) { next(e); }
});

r.post('/dns/check', async (req, res, next) => {
  try {
    const { verificationId } = z.object({ verificationId: z.string().min(1).max(64) }).parse(req.body);
    enforce(`vid:${verificationId}:dnscheck`, 1, 5_000); // >= 5s between checks
    const out = await dnsChallenge.check(verificationId);
    if (out.status === 'not_found') return res.status(404).json({ error: 'not_found' });
    audit('dns_check', { verificationId, outcome: out.status });
    res.json({ status: out.status === 'verified' ? 'verified' : out.status, found: out.found, attempts: out.attempts });
  } catch (e) { next(e); }
});

// ---- Status + claim ----
r.get('/:id/status', (req, res, next) => {
  try {
    const claimSecret = z.string().min(1).max(128).parse(req.query.claimSecret);
    const s = verifications.statusFor(req.params.id, claimSecret);
    if (!s) return res.status(404).json({ error: 'not_found' });
    res.json(s);
  } catch (e) { next(e); }
});

r.post('/:id/claim', (req, res, next) => {
  try {
    const { claimSecret } = z.object({ claimSecret: z.string().min(1).max(128) }).parse(req.body);
    const out = verifications.claim(req.params.id, claimSecret);
    if (out.error) return res.status(out.status || 409).json({ error: out.error });
    audit('claim', { verificationId: req.params.id, domain: out.grant.domain, outcome: 'granted' });
    res.json({ grant: out.grant.token, domain: out.grant.domain, expiresAt: out.grant.expiresAt, maxUses: out.grant.maxUses });
  } catch (e) { next(e); }
});

function confirmErrorPage(reason) {
  const msg = {
    expired: 'הקישור פג תוקף. התחילו אימות מחדש.',
    used: 'הקישור כבר נוצל. כל קישור תקף לשימוש אחד בלבד.',
    locked: 'יותר מדי ניסיונות. נסו שוב מאוחר יותר.',
    invalid: 'קישור לא תקין.',
  }[reason] || 'קישור לא תקין.';
  return `<!doctype html><html lang="he" dir="rtl"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>אימות PHP2Shell</title>
<body style="font-family:system-ui,Arial,sans-serif;background:#0a0e13;color:#e9eef4;display:grid;place-items:center;min-height:100vh;margin:0">
<main style="max-width:420px;text-align:center;padding:28px">
<h1 style="font-size:20px;margin:0 0 10px">לא ניתן לאמת</h1>
<p style="color:#9da9b7;line-height:1.6">${msg}</p>
<p style="margin-top:20px"><a href="${config.HUB_URL}/scan.html" style="color:#3bbdd9">חזרה לכלי האימות</a></p>
</main></body></html>`;
}

export default r;
