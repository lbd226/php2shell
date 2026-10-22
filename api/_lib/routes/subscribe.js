// Newsletter sign-up with double opt-in. A POST stores a short-lived pending
// record and emails a one-time confirmation link; only after the recipient
// clicks it is the address added to the confirmed list. Every confirmation
// carries a single-click unsubscribe link. No address is confirmed without a
// click, so the list cannot be poisoned with other people's emails.
import { Router } from 'express';
import { z } from 'zod';
import { config, tokens, sendMail, emailEnabled } from '../core.js';
import { redis, hex, fromHex } from '../redis.js';
import { limiters, enforce } from '../ratelimit.js';
import { audit } from '../audit.js';

const r = Router();

const clientIp = (req) =>
  req.headers['x-real-ip'] || (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.ip || 'unknown';

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const subSchema = z.object({
  email: z.string().min(3).max(254).refine((v) => EMAIL_RE.test(v.trim()), 'invalid email'),
  consent: z.literal(true),
});

const PEND_TTL = 86400; // 24h to confirm

const readJson = (raw) => (raw == null ? null : typeof raw === 'string' ? JSON.parse(raw) : raw);

function page(body) {
  return `<!doctype html><html lang="he" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>PHP2Shell</title>
<style>:root{color-scheme:dark}body{margin:0;background:#0a0d14;color:#eef1f6;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","Arial Hebrew",Arial,sans-serif;display:grid;min-height:100vh;place-items:center;padding:24px}
.c{max-width:460px;width:100%;background:#141a24;border:1px solid #232c3a;border-radius:16px;padding:32px;text-align:center;box-sizing:border-box}
.c h1{margin:0 0 10px;font-size:22px}.c p{color:#97a2b2;line-height:1.65;margin:0 0 18px}
.ic{font-size:40px;line-height:1}a.btn{display:inline-block;background:#6ea0ff;color:#081019;font-weight:700;text-decoration:none;padding:11px 22px;border-radius:10px}
a.u{color:#97a2b2;font-size:12px}</style></head><body><div class="c">${body}</div></body></html>`;
}
const home = config.HUB_URL;

// POST /api/subscribe
r.post('/', async (req, res, next) => {
  try {
    if (!emailEnabled) return res.status(503).json({ error: 'email_disabled' });
    const { email } = subSchema.parse(req.body);
    const addr = email.trim();
    const lower = addr.toLowerCase();

    await enforce(limiters.ipSubscribe, tokens.hashIp(clientIp(req)));
    await enforce(limiters.rcptSubscribe, lower);

    if (await redis.sismember('sub:emails', lower)) return res.status(200).json({ ok: true, already: true });

    const t = tokens.makeSplitToken();
    await redis.set('sub:pend:' + t.selector, JSON.stringify({ vh: hex(t.verifierHash), email: addr, ts: Date.now() }), { ex: PEND_TTL });

    const link = `${config.PUBLIC_BASE_URL}/api/subscribe/confirm?token=${encodeURIComponent(t.token)}`;
    await sendMail({
      to: addr,
      subject: 'אישור הרשמה לעדכוני PHP2Shell',
      html: confirmEmailHtml(link),
      text: `אישור הרשמה לעדכוני אבטחה של PHP2Shell.\n\nלאישור ההרשמה (הקישור תקף 24 שעות, שימוש חד-פעמי):\n${link}\n\nאם לא נרשמת, התעלם מהודעה זו.`,
    });
    await audit('subscribe_start', { outcome: 'sent' });
    res.status(202).json({ ok: true });
  } catch (e) { next(e); }
});

// GET /api/subscribe/confirm?token=selector.verifier
r.get('/confirm', async (req, res, next) => {
  try {
    const p = tokens.parseSplitToken(typeof req.query.token === 'string' ? req.query.token : '');
    if (!p) return res.status(400).type('html').send(page(`<div class="ic">⚠️</div><h1>קישור לא תקין</h1><p>Invalid link.</p><a class="btn" href="${home}">php2shell.ai</a>`));

    const key = 'sub:pend:' + p.selector;
    const rec = readJson(await redis.get(key));
    if (!rec || !tokens.matchesHash(p.verifier, fromHex(rec.vh))) {
      return res.status(410).type('html').send(page(`<div class="ic">⏳</div><h1>הקישור פג או כבר נוצל</h1><p>This link has expired or was already used.</p><a class="btn" href="${home}">php2shell.ai</a>`));
    }
    await redis.del(key); // single-use

    const lower = String(rec.email).toLowerCase();
    await redis.sadd('sub:emails', lower);
    const u = tokens.makeSplitToken();
    await redis.set('sub:unsub:' + u.selector, JSON.stringify({ vh: hex(u.verifierHash), email: lower }));
    await redis.set('sub:utok:' + lower, u.token);
    await audit('subscribe_confirm', { outcome: 'confirmed' });

    const unsub = `${config.PUBLIC_BASE_URL}/api/subscribe/unsubscribe?token=${encodeURIComponent(u.token)}`;
    res.status(200).type('html').send(page(
      `<div class="ic">✓</div><h1>נרשמת בהצלחה</h1><p>תודה! נעדכן אותך על חולשות PHP חדשות ומידע אבטחה חשוב. אפשר לבטל בכל רגע.<br>You are subscribed.</p><a class="btn" href="${home}">חזרה לאתר</a><p style="margin-top:16px"><a class="u" href="${unsub}">ביטול הרשמה · Unsubscribe</a></p>`
    ));
  } catch (e) { next(e); }
});

// GET /api/subscribe/unsubscribe?token=selector.verifier
r.get('/unsubscribe', async (req, res, next) => {
  try {
    const p = tokens.parseSplitToken(typeof req.query.token === 'string' ? req.query.token : '');
    if (p) {
      const rec = readJson(await redis.get('sub:unsub:' + p.selector));
      if (rec && tokens.matchesHash(p.verifier, fromHex(rec.vh))) {
        await redis.srem('sub:emails', rec.email);
        await redis.del('sub:unsub:' + p.selector);
        await redis.del('sub:utok:' + rec.email);
        await audit('unsubscribe', { outcome: 'removed' });
      }
    }
    res.status(200).type('html').send(page(`<div class="ic">👋</div><h1>ההרשמה בוטלה</h1><p>הוסרת מרשימת התפוצה. You have been unsubscribed.</p><a class="btn" href="${home}">php2shell.ai</a>`));
  } catch (e) { next(e); }
});

function confirmEmailHtml(link) {
  return `<!doctype html><html lang="he" dir="rtl"><head><meta charset="utf-8"></head>
<body style="margin:0;background:#0a0d14;font-family:-apple-system,'Segoe UI',Arial,sans-serif;color:#eef1f6">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="padding:28px 16px"><tr><td align="center">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:520px;background:#141a24;border:1px solid #232c3a;border-radius:16px;overflow:hidden">
<tr><td style="padding:22px 26px;border-bottom:1px solid #232c3a;font-weight:800;font-size:18px"><span style="color:#eef1f6">PHP2</span><span style="color:#6ea0ff">Shell</span></td></tr>
<tr><td style="padding:26px">
<h1 style="margin:0 0 10px;font-size:21px">אישור הרשמה לעדכונים</h1>
<p style="margin:0 0 18px;color:#97a2b2;line-height:1.6">לחצו לאישור ההרשמה לקבלת עדכוני אבטחה על חולשות PHP. הקישור תקף 24 שעות ולשימוש חד-פעמי.</p>
<p style="margin:0 0 22px"><a href="${link}" style="display:inline-block;background:#6ea0ff;color:#081019;text-decoration:none;font-weight:700;padding:13px 26px;border-radius:10px">אישור ההרשמה</a></p>
<p style="margin:0 0 6px;color:#79838f;font-size:12.5px">אם הכפתור לא עובד, העתיקו את הקישור:</p>
<p style="margin:0 0 18px;direction:ltr;word-break:break-all;font-family:monospace;font-size:11.5px;color:#7f8a99">${link}</p>
<p style="margin:0;color:#79838f;font-size:12px;line-height:1.6;border-top:1px solid #232c3a;padding-top:16px">אם לא נרשמת — התעלם מהודעה זו ולא תתווסף לרשימה.</p>
</td></tr></table></td></tr></table></body></html>`;
}

export default r;
