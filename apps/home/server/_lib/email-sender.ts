// Swappable email sender (email-auth OTP + org invite links). Gated + DEPLOY-SAFE: with no provider
// key set, it LOGS the message and returns ok — the build/flows never break; set SENDGRID_API_KEY +
// EMAIL_FROM (a verified sender) to send for real. Uses the SendGrid v3 REST API directly (no npm dep →
// provider stays swappable, build stays lean).
import { signBridgeCall } from './bridge-hmac';

export interface EmailEnv {
  /** The a2a Worker that holds the Cloudflare Email Service binding (spec 365). When set, EVERY mail this
   *  Home sends goes out through its `/email/send`: as a person or an organization under their session, or
   *  as system mail (a sign-in code) under the HMAC bridge envelope the custody routes already use. */
  A2A_CUSTODY_URL?: string;
  A2A_CUSTODY_BRIDGE_SECRET?: string;
  SENDGRID_API_KEY?: string;
  /** Verified sender, e.g. `no-reply@impact-agent.me` — REQUIRED by SendGrid (must be a verified sender/domain). */
  EMAIL_FROM?: string;
}

export interface OutboundEmail {
  to: string;
  subject: string;
  html: string;
  text?: string;
  /** Reply-To — e.g. a relying app's own inbox for the invites Home sends for it. */
  replyTo?: string;
}

/** True once a provider is configured — the UI shows "email login/invite available" only when this is set. */
export function emailSendingEnabled(env: EmailEnv): boolean {
  return !!(env.A2A_CUSTODY_URL?.trim() && env.A2A_CUSTODY_BRIDGE_SECRET?.trim()) || !!(env.SENDGRID_API_KEY && env.SENDGRID_API_KEY.trim() && env.EMAIL_FROM && env.EMAIL_FROM.trim());
}

/** Who the mail goes out as, when a steward sends it for an organization through the Worker rail. */
export interface SendAs { session: string; as: string }

export async function sendEmail(env: EmailEnv, msg: OutboundEmail, sendAs?: SendAs): Promise<{ ok: boolean; error?: string }> {
  const key = env.SENDGRID_API_KEY?.trim();
  const from = env.EMAIL_FROM?.trim();
  // THE WORKER RAIL (Cloudflare Email Service) — the ONE rail when the Worker is configured. This Home runs
  // where no email binding exists; the a2a Worker holds one, sends from a zone onboarded to Email Sending,
  // and threads a person's or organization's copy into their own inbox. A person's mail carries their
  // session; system mail (a sign-in code, a verification) carries the HMAC bridge envelope. Chosen by
  // configuration, never by a failed attempt (ADR-0013); SendGrid remains only for a deployment without it.
  const a2a = env.A2A_CUSTODY_URL?.trim();
  if (a2a && env.A2A_CUSTODY_BRIDGE_SECRET?.trim()) {
    try {
      const payload = { to: msg.to, subject: msg.subject, text: msg.text ?? '', ...(msg.html ? { html: msg.html } : {}), ...(msg.replyTo ? { replyTo: msg.replyTo } : {}) };
      const url = `${a2a.replace(/\/$/, '')}/email/send`;
      const r = sendAs
        ? await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ ...payload, session: sendAs.session, as: sendAs.as }) })
        : await (async () => {
            const envelope = await signBridgeCall({ secret: env.A2A_CUSTODY_BRIDGE_SECRET!, audience: 'email.send', payload });
            return fetch(url, { method: 'POST', headers: envelope.headers, body: envelope.body });
          })();
      const body = (await r.json().catch(() => ({}))) as { ok?: boolean; error?: string; via?: string };
      if (!r.ok || body.ok === false) return { ok: false, error: body.error ?? `worker email ${r.status}` };
      return { ok: true };
    } catch (e) {
      return { ok: false, error: e instanceof Error ? e.message : 'email send failed' };
    }
  }
  if (!key || !from) {
    // No provider → don't fail; log so a dev can grab the OTP/link locally (deploy-safe).
    console.log(`[email-sender] (SENDGRID_API_KEY/EMAIL_FROM unset) would send to ${msg.to} — "${msg.subject}"`);
    return { ok: true };
  }
  try {
    const res = await fetch('https://api.sendgrid.com/v3/mail/send', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${key}` },
      body: JSON.stringify({
        personalizations: [{ to: [{ email: msg.to }] }],
        from: { email: from },
        ...(msg.replyTo ? { reply_to: { email: msg.replyTo } } : {}),
        subject: msg.subject,
        content: [
          ...(msg.text ? [{ type: 'text/plain', value: msg.text }] : []),
          { type: 'text/html', value: msg.html },
        ],
      }),
    });
    // SendGrid returns 202 Accepted on success.
    if (!res.ok) return { ok: false, error: `sendgrid ${res.status}` };
    return { ok: true };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : 'email send failed' };
  }
}

const wrap = (inner: string, brand: string): string =>
  `<div style="font-family:system-ui,sans-serif;max-width:440px;margin:auto;padding:24px">
     <p style="font-size:13px;color:#6b7280;margin:0 0 16px">${brand}</p>${inner}
     <p style="font-size:12px;color:#9ca3af;margin-top:24px">If you didn't request this, you can ignore this email.</p>
   </div>`;

export function otpEmail(to: string, otp: string, brand: string): OutboundEmail {
  return {
    to,
    subject: `${otp} is your ${brand} sign-in code`,
    text: `Your ${brand} sign-in code is ${otp}. It expires in 10 minutes.`,
    html: wrap(`<p style="font-size:15px">Your sign-in code:</p>
      <p style="font-size:30px;font-weight:700;letter-spacing:4px;margin:8px 0">${otp}</p>
      <p style="font-size:13px;color:#6b7280">Expires in 10 minutes.</p>`, brand),
  };
}

/** `appName` names the relying app this invitation is TO — the org is the community inside it. */
export function inviteEmail(to: string, joinUrl: string, orgName: string, brand: string, appName?: string | null, declineUrl?: string | null): OutboundEmail {
  const subject = appName ? `You're invited to ${appName} (${orgName})` : `You're invited to join ${orgName}`;
  const lead = appName
    ? `You've been invited to ${appName} to join ${orgName}.`
    : `You've been invited to join ${orgName} on ${brand}.`;
  const detail = appName
    ? `Click below to accept — we'll set up your home, then take you to ${appName} as a member of ${orgName}.`
    : `Click below to accept — you'll confirm your email, choose the name your team sees, then join.`;
  return {
    to,
    subject,
    text: `${lead} ${detail} Join here: ${joinUrl}${declineUrl ? `\n\nNot interested? ${declineUrl}` : ''}`,
    html: wrap(`<p style="font-size:15px"><b>${lead}</b></p>
      <p style="font-size:13px;color:#6b7280;margin:8px 0 16px">${detail}</p>
      <a href="${joinUrl}" style="display:inline-block;background:#4338ca;color:#fff;text-decoration:none;padding:10px 18px;border-radius:8px;font-weight:600">Accept invitation</a>${declineUrl ? `
      <p style="font-size:11px;color:#9ca3af;margin-top:28px"><a href="${declineUrl}" style="color:#9ca3af;text-decoration:underline">Not interested</a></p>` : ''}`, brand),
  };
}
