// Email transport. Prefers Resend; falls back to SMTP (nodemailer) when no Resend key is set.
// Providers are imported lazily so the server boots even if a provider package is absent
// and the email challenge is simply disabled.
import { config } from '../config.js';

let resendClient = null;
let smtpTransport = null;

async function getResend() {
  if (!resendClient) {
    const { Resend } = await import('resend');
    resendClient = new Resend(config.RESEND_API_KEY);
  }
  return resendClient;
}

async function getSmtp() {
  if (!smtpTransport) {
    const nodemailer = (await import('nodemailer')).default;
    smtpTransport = nodemailer.createTransport({
      host: config.SMTP_HOST,
      port: config.SMTP_PORT,
      secure: config.SMTP_SECURE,
      auth: config.SMTP_USER ? { user: config.SMTP_USER, pass: config.SMTP_PASS } : undefined,
    });
  }
  return smtpTransport;
}

// to is a single, already-validated recipient address (host === verified domain).
// subject/html/text are built by the backend; the caller never injects headers.
export async function sendMail({ to, subject, html, text }) {
  if (config.emailProvider === 'resend') {
    const resend = await getResend();
    const { data, error } = await resend.emails.send({
      from: config.MAIL_FROM,
      to: [to],
      subject,
      html,
      text,
    });
    if (error) throw new Error(`resend send failed: ${error.message || error.name || 'unknown'}`);
    return { id: data?.id ?? null, provider: 'resend' };
  }
  if (config.emailProvider === 'smtp') {
    const t = await getSmtp();
    const info = await t.sendMail({ from: config.MAIL_FROM, to, subject, html, text });
    return { id: info.messageId, provider: 'smtp' };
  }
  throw new Error('email provider not configured');
}

export const emailEnabled = config.emailEnabled;
export const emailProvider = config.emailProvider;
