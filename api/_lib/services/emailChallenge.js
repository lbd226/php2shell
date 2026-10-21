// Email challenge for Vercel. The HTML template is inlined (serverless functions don't reliably
// bundle sibling non-JS files), reusing the hub's palette.
import { config, sendMail, tokens } from '../core.js';
import * as verification from './verification.js';

export function maskRecipient(email) {
  const at = email.indexOf('@');
  if (at <= 0) return '***';
  const local = email.slice(0, at);
  const host = email.slice(at + 1);
  const shown = local.slice(0, Math.min(2, local.length));
  return `${shown}${'*'.repeat(Math.max(1, local.length - shown.length))}@${host}`;
}

function emailHtml({ link, domain, minutes }) {
  return `<!doctype html><html lang="he" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;background:#eef1f5;font-family:'Heebo',-apple-system,'Segoe UI',Arial,sans-serif;color:#0e141c">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#eef1f5;padding:28px 16px"><tr><td align="center">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:520px;background:#fff;border:1px solid #d6dce4;border-radius:16px;overflow:hidden">
<tr><td style="padding:22px 26px;border-bottom:1px solid #d6dce4;font-weight:800;font-size:18px"><span style="color:#0e141c">PHP2</span><span style="color:#0c6b86">Shell</span></td></tr>
<tr><td style="padding:26px">
<h1 style="margin:0 0 10px;font-size:21px">אימות בעלות על הדומיין</h1>
<p style="margin:0 0 6px;color:#515c6a;line-height:1.6">התבקש אימות בעלות עבור:</p>
<p style="margin:0 0 20px;font-family:monospace;direction:ltr;font-size:15px;font-weight:600;background:#f7f9fb;border:1px solid #d6dce4;border-radius:10px;padding:10px 12px">${domain}</p>
<p style="margin:0 0 20px;color:#515c6a;line-height:1.6">לאישור, לחצו על הכפתור. הקישור תקף ל‑<strong>${minutes} דקות</strong> ולשימוש <strong>חד‑פעמי</strong>.</p>
<p style="margin:0 0 22px"><a href="${link}" style="display:inline-block;background:#0c6b86;color:#fff;text-decoration:none;font-weight:700;padding:13px 26px;border-radius:10px">אישור בעלות</a></p>
<p style="margin:0 0 6px;color:#79838f;font-size:12.5px">אם הכפתור לא עובד, העתיקו את הקישור:</p>
<p style="margin:0 0 20px;direction:ltr;word-break:break-all;font-family:monospace;font-size:11.5px;color:#5f6875">${link}</p>
<p style="margin:0;color:#79838f;font-size:12px;line-height:1.6;border-top:1px solid #d6dce4;padding-top:16px">אם לא ביקשתם אימות זה — התעלמו מהודעה זו. איננו מנצלים חולשות ואיננו סורקים אתרים ללא הוכחת בעלות.</p>
</td></tr></table></td></tr></table></body></html>`;
}

export async function startAndSend({ domain, emailAddress }) {
  const v = await verification.createEmail({ domain, emailAddress });
  const link = `${config.PUBLIC_BASE_URL}/api/verify/email/confirm?token=${encodeURIComponent(v.token)}`;
  const minutes = Math.round(config.ttl.emailMs / 60000);
  const html = emailHtml({ link, domain, minutes });
  const text = `אימות בעלות על ${domain}\n\nלאישור (תקף ${minutes} דקות, שימוש חד-פעמי):\n${link}\n\nאם לא ביקשתם זאת, התעלמו מהודעה זו.`;
  await sendMail({ to: emailAddress, subject: `אימות בעלות על ${domain} — PHP2Shell`, html, text });
  return { verificationId: v.id, claimSecret: v.claimSecret, method: 'email', maskedRecipient: maskRecipient(emailAddress), expiresAt: v.expiresAt };
}

export async function confirm(token) {
  const p = tokens.parseSplitToken(token);
  if (!p) return { ok: false, reason: 'invalid' };
  return verification.markVerifiedByEmail(p.selector, p.verifier);
}
