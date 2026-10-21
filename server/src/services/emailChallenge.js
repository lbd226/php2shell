// Email ownership challenge: send a one-time link to an address AT the domain, then confirm.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { config } from '../config.js';
import { sendMail } from '../lib/mailer.js';
import { parseSplitToken } from '../lib/tokens.js';
import * as verifications from './verificationService.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const TEMPLATE = fs.readFileSync(path.join(__dirname, '..', 'templates', 'verify-email.html'), 'utf8');

export function maskRecipient(email) {
  const at = email.indexOf('@');
  if (at <= 0) return '***';
  const local = email.slice(0, at);
  const host = email.slice(at + 1);
  const shown = local.slice(0, Math.min(2, local.length));
  return `${shown}${'*'.repeat(Math.max(1, local.length - shown.length))}@${host}`;
}

function render(template, vars) {
  return template.replace(/\{\{(\w+)\}\}/g, (_, k) => (k in vars ? String(vars[k]) : ''));
}

// Create a verification and send the email. Returns public fields (never the token).
export async function startAndSend({ domain, emailAddress, ipHash = null }) {
  const v = verifications.createEmail({ domain, emailAddress, ipHash });
  const link = `${config.PUBLIC_BASE_URL}/api/verify/email/confirm?token=${encodeURIComponent(v.token)}`;
  const minutes = Math.round(config.ttl.emailMs / 60000);

  const html = render(TEMPLATE, { LINK: link, DOMAIN: domain, MINUTES: minutes });
  const text =
    `אימות בעלות על הדומיין ${domain}\n\n` +
    `לאישור, פִתחו את הקישור הבא (תקף ל-${minutes} דקות, שימוש חד-פעמי):\n${link}\n\n` +
    `אם לא ביקשתם זאת, התעלמו מהודעה זו.`;

  await sendMail({ to: emailAddress, subject: `אימות בעלות על ${domain} — PHP2Shell`, html, text });
  verifications.recordSent(v.id);

  return { verificationId: v.id, claimSecret: v.claimSecret, method: 'email', maskedRecipient: maskRecipient(emailAddress), expiresAt: v.expiresAt };
}

// Handle the confirmation link. Returns { ok, id?, reason? }.
export function confirm(token) {
  const parsed = parseSplitToken(token);
  if (!parsed) return { ok: false, reason: 'invalid' };
  return verifications.markVerifiedByEmail(parsed.selector, parsed.verifier);
}
