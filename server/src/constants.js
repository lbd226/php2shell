// Single source of truth for the vulnerability data, mirrored to the hub via /api/version-table.
// Keep this map identical to the client-side PATCHED map in index.html.

export const PATCHED = { '8.5': 12, '8.4': 27, '8.3': 36, '8.2': 35 };

// Branches 7.4 .. 8.1 (and older) received no official fixed release — only partial source backports.
export const EOL_RANGE = '7.4-8.1';

export const CVES = ['CVE-2026-109618', 'CVE-2026-109619'];

// RFC 2142 well-known administrative mailboxes allowed for the email challenge.
export const RFC2142_MAILBOXES = ['admin', 'security', 'webmaster', 'postmaster', 'hostmaster'];

export const DISCLAIMER_HE =
  'זוהי הערכת תנוחה מבוססת-גרסה, שנגזרת מכותרת שהשרת עצמו חושף — ולא הוכחה לפגיעוּת. ' +
  'כותרות עלולות להיות ישנות, מזויפות או מוסתרות. ודאו תמיד מול ההודעות הרשמיות של PHP.net והספקים.';

export const REMEDIATION_URL = 'https://php2shell.com';

// Human-readable, Hebrew verdict messages keyed by verdict code.
export function verdictMessage(verdict, { branch, inferredVersion, patchedVersion } = {}) {
  switch (verdict) {
    case 'vulnerable':
      return `גרסה ${inferredVersion} חשופה ל‑PHP2Shell. שדרגו ל‑${branch}.${PATCHED[branch]} ומעלה והפעילו מחדש את תהליכי ה‑PHP.`;
    case 'patched':
      return `גרסה ${inferredVersion} כוללת את התיקון (${branch}.${PATCHED[branch]} ומעלה). ודאו שכל הסביבות — כולל CLI ו‑cron — על אותה גרסה.`;
    case 'eol':
      return `ענף ${branch} הגיע לסוף חיים ולא קיבל גרסה רשמית מתוקנת. המסלול הבטוח: מעבר לענף נתמך — 8.2.35 ומעלה.`;
    case 'unknown_branch':
      return `ענף ${branch} אינו ברשימת הענפים הידועה לכלי. בדקו ישירות בהודעה הרשמית של PHP.net.`;
    case 'unknown_hidden':
      return 'השרת אינו חושף את גרסת ה‑PHP (expose_php=Off או שהכותרת הוסרה) — וזו היגיינה טובה. איננו מנחשים. ודאו פנימית עם php -v / phpinfo() בשרת שבבעלותכם.';
    default:
      return 'לא ניתן היה להשלים את הבדיקה.';
  }
}
