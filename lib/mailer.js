// ── Outbound alert email, via Resend ────────────────────────────────────────
// No email provider is configured anywhere in this app yet — every existing
// "deliver a link" flow (password reset, invites) works around that by just
// showing the link on-screen. Alerts can't use that trick: the whole point is
// that nobody's looking at the dashboard when one should fire, so this is the
// first feature that genuinely needs a real outbound email channel.
//
// Until RESEND_API_KEY is set (Render env var — see README/CHANGES note),
// sendMail() logs what it would have sent instead of throwing, so the rest of
// the alert engine can be built, tested, and deployed before that account
// exists. Once the key is added and the service restarts, real emails start
// flowing with no code change.
let resendClient = null;
function getClient() {
  if (!process.env.RESEND_API_KEY) return null;
  if (!resendClient) {
    const { Resend } = require('resend');
    resendClient = new Resend(process.env.RESEND_API_KEY);
  }
  return resendClient;
}

// Resend's shared sandbox sender works with no domain setup at all, but only
// delivers reliably to the account owner's own verified address — fine for
// initial testing, not for real client delivery. Once Ian verifies a sending
// domain in Resend, set ALERT_FROM_EMAIL (e.g. "Wachadoin Alerts
// <alerts@wachadoin.com>") and it's used automatically, no code change.
const FROM = process.env.ALERT_FROM_EMAIL || 'Wachadoin Alerts <onboarding@resend.dev>';

async function sendMail({ to, subject, html }) {
  const client = getClient();
  if (!client) {
    console.log(`[mailer] RESEND_API_KEY not set — would have emailed ${to}: "${subject}"`);
    return { sent: false, reason: 'no-provider-configured' };
  }
  try {
    await client.emails.send({ from: FROM, to, subject, html });
    return { sent: true };
  } catch (err) {
    console.error('[mailer] send failed:', err.message);
    return { sent: false, reason: err.message };
  }
}

module.exports = { sendMail };
