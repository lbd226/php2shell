import { Router } from 'express';
import { z } from 'zod';
import { config, normalizeDomain, emailHostMatchesDomain, DomainError, tokens, constants, emailEnabled } from '../core.js';
import { limiters, enforce } from '../ratelimit.js';
import { audit } from '../audit.js';
import * as emailChallenge from '../services/emailChallenge.js';
import * as dnsChallenge from '../services/dnsChallenge.js';
import * as verification from '../services/verification.js';

const r = Router();

// On Vercel, x-real-ip is set by the platform from the real connection (not client-forgeable).
function clientIp(req) {
  return req.headers['x-real-ip'] || (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.ip || 'unknown';
}
const ipHashOf = (req) => tokens.hashIp(clientIp(req));

const emailStartSchema = z.object({
  domain: z.string().min(1).max(253),
  email: z.string().max(254).optional(),
  localpart: z.enum(constants.RFC2142_MAILBOXES).optional(),
});

r.post('/email/start', async (req, res, next) => {
  try {
    if (!emailEnabled) return res.status(503).json({ error: 'email_disabled', message: 'שער המייל אינו מוגדר; השתמשו באתגר DNS TXT' });
    const body = emailStartSchema.parse(req.body);
    const domain = normalizeDomain(body.domain);

    let recipient;
    if (body.email) {
      if (!emailHostMatchesDomain(body.email, domain)) throw new DomainError('כתובת המייל חייבת להיות על אותו דומיין בדיוק שאתם מאמתים');
      recipient = body.email.trim();
    } else {
      recipient = `${body.localpart || 'admin'}@${domain}`;
    }

    const ipHash = ipHashOf(req);
    await enforce(limiters.ipVerify, ipHash);
    await enforce(limiters.domainEmail, domain);
    await enforce(limiters.rcptEmail, recipient.toLowerCase());

    const out = await emailChallenge.startAndSend({ domain, emailAddress: recipient });
    await audit('email_sent', { verificationId: out.verificationId, domain, ipHash, outcome: 'sent' });
    res.status(202).json(out);
  } catch (e) { next(e); }
});

r.get('/email/confirm', async (req, res, next) => {
  try {
    const token = typeof req.query.token === 'string' ? req.query.token : '';
    const out = await emailChallenge.confirm(token);
    if (out.ok) {
      await audit('confirm', { verificationId: out.id, domain: out.domain, outcome: 'verified' });
      return res.redirect(302, `${config.HUB_URL}/scan.html#verified=1&id=${encodeURIComponent(out.id)}&cs=${encodeURIComponent(out.confirmSecret)}`);
    }
    const statusMap = { expired: 410, used: 410, locked: 429, invalid: 400 };
    res.status(statusMap[out.reason] || 400).type('html; charset=utf-8').send(confirmErrorPage(out.reason));
  } catch (e) { next(e); }
});

r.post('/dns/start', async (req, res, next) => {
  try {
    const { domain: raw } = z.object({ domain: z.string().min(1).max(253) }).parse(req.body);
    const domain = normalizeDomain(raw);
    const ipHash = ipHashOf(req);
    await enforce(limiters.ipVerify, ipHash);
    await enforce(limiters.domainDns, domain);
    const out = await dnsChallenge.start({ domain });
    await audit('verify_start', { verificationId: out.verificationId, domain, ipHash, outcome: 'dns' });
    res.json(out);
  } catch (e) { next(e); }
});

r.post('/dns/check', async (req, res, next) => {
  try {
    const { verificationId } = z.object({ verificationId: z.string().min(1).max(64) }).parse(req.body);
    await enforce(limiters.dnsCheck, verificationId);
    const out = await dnsChallenge.check(verificationId);
    if (out.status === 'not_found') return res.status(404).json({ error: 'not_found' });
    await audit('dns_check', { verificationId, outcome: out.status });
    res.json({ status: out.status === 'verified' ? 'verified' : out.status, found: out.found });
  } catch (e) { next(e); }
});

r.post('/:id/status', async (req, res, next) => {
  try {
    const { claimSecret } = z.object({ claimSecret: z.string().min(1).max(128) }).parse(req.body);
    const s = await verification.statusFor(req.params.id, claimSecret);
    if (!s) return res.status(404).json({ error: 'not_found' });
    res.json(s);
  } catch (e) { next(e); }
});

r.post('/:id/claim', async (req, res, next) => {
  try {
    const { claimSecret } = z.object({ claimSecret: z.string().min(1).max(128) }).parse(req.body);
    const out = await verification.claim(req.params.id, claimSecret);
    if (out.error) return res.status(out.status || 409).json({ error: out.error });
    await audit('claim', { verificationId: req.params.id, domain: out.grant.domain, outcome: 'granted' });
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
  return `<!doctype html><html lang="he" dir="rtl"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>אימות PHP2Shell</title>
<body style="font-family:system-ui,Arial,sans-serif;background:#0a0e13;color:#e9eef4;display:grid;place-items:center;min-height:100vh;margin:0">
<main style="max-width:420px;text-align:center;padding:28px"><h1 style="font-size:20px;margin:0 0 10px">לא ניתן לאמת</h1>
<p style="color:#9da9b7;line-height:1.6">${msg}</p>
<p style="margin-top:20px"><a href="${config.HUB_URL}/scan.html" style="color:#3bbdd9">חזרה לכלי האימות</a></p></main></body></html>`;
}

export default r;
