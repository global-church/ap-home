// POST /connect/email/start — send a one-time 6-digit code to an email (email-auth, login-grade).
//   body: { email, aud? }
// The OTP record is keyed by SHA-256(email) (NOT the code — so a code can't be brute-forced blindly;
// verification requires knowing the email, and per-email attempts are bounded in email-verify). The raw
// email is never stored. Deploy-safe: with no SendGrid key the sender logs (no send), still returns ok.
import type { FnContext } from '../_lib/server-broker';
import { sendEmail, otpEmail, emailSendingEnabled } from '../_lib/email-sender';
import { emailHash } from '../../src/lib/kv-indexer';
import { whitelabel } from '../../src/whitelabel/config';
import { CODE_SEND_FAILED, reportHomeError } from '../_lib/home-sentry';

const cors = { 'access-control-allow-origin': '*', 'access-control-allow-headers': 'content-type' };
const json = (b: unknown, s = 200): Response =>
  new Response(JSON.stringify(b), { status: s, headers: { 'content-type': 'application/json', ...cors } });

export const onRequestOptions = async (): Promise<Response> => new Response(null, { status: 204, headers: cors });

/** A second request for the same email inside this window sends nothing (the first email is on its way). */
const RESEND_GAP_MS = 30_000;

const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

/** 6-digit cryptographically-random code. */
function newOtp(): string {
  const n = crypto.getRandomValues(new Uint32Array(1))[0]! % 1_000_000;
  return n.toString().padStart(6, '0');
}

export const onRequestPost = async ({ request, env }: FnContext): Promise<Response> => {
  const body = (await request.json().catch(() => null)) as { email?: string; aud?: string; app?: string } | null;
  const email = (body?.email ?? '').trim().toLowerCase();
  if (!EMAIL_RE.test(email)) return json({ error: 'a valid email is required' }, 400);

  // ONE code per email while it is valid (Paul, 2026-10-15: "two emails with different codes"). A second
  // request — a double click, Enter then click, or Resend — used to mint a NEW code over the first, so the
  // email that arrived first no longer worked. Now an unexpired code is sent again, and a repeat within
  // RESEND_GAP_MS sends nothing at all (the first email is already on its way). Attempts are kept, so a
  // resend is not a way around the guess limit.
  const key = `emailotp:${await emailHash(email)}`;
  const prev = await env.AUTH_CODES.get(key)
    .then((raw) => (raw ? (JSON.parse(raw) as { code?: string; aud?: string; attempts?: number; issuedAt?: number; sentAt?: number }) : null))
    .catch(() => null);
  const now = Date.now();
  const reuse = prev?.code && /^\d{6}$/.test(prev.code) ? prev : null;
  if (reuse && reuse.sentAt && now - reuse.sentAt < RESEND_GAP_MS) {
    return json({ ok: true, delivery: emailSendingEnabled(env) ? 'sent' : 'logged', repeated: true });
  }
  const code = reuse?.code ?? newOtp();
  // A reused code keeps its ORIGINAL ten minutes — resending does not extend a code's life.
  const ttl = { expirationTtl: reuse?.issuedAt ? Math.max(60, 600 - Math.floor((now - reuse.issuedAt) / 1000)) : 600 };
  const record = (sentAt: number) =>
    JSON.stringify({
      code,
      aud: body?.aud ?? env.DEMO_SSO_AUD ?? 'demo-sso',
      attempts: reuse?.attempts ?? 0,
      issuedAt: reuse?.issuedAt ?? now,
      sentAt,
    });
  // The code is stored BEFORE the send (the email must never carry a code verify does not know), but "sent" is
  // recorded only AFTER the email was accepted (Ryan, 2026-10-15: a failed send was remembered as sent, so the
  // retry inside RESEND_GAP_MS sent nothing and said nothing).
  await env.AUTH_CODES.put(key, record(reuse?.sentAt ?? 0), ttl);

  // The relying app this sign-in is for (its client_id, sent by an enroll window): its support inbox goes on the
  // code email as Reply-To and a help line (Gather, 2026-10-16). Unknown or absent → the plain email as before.
  // `app`, NOT `aud`: the audience decides whether a NEW account may be created at verify (custody is for the
  // Home's own audience), so a relying app's client_id must never ride there — it did for an hour on
  // 2026-10-16 and new hosts were told "we couldn't set up a home for this email".
  const app = body?.app ? whitelabel.relyingApps.find((a) => a.client_id === body.app) : undefined;
  const sent = await sendEmail(env, otpEmail(email, code, whitelabel.brand.name, app ? { name: app.name, replyTo: app.replyTo } : undefined));
  if (!sent.ok) {
    // The person gets a plain message; the provider's error goes to Sentry (Clayton, 2026-10-20: a host was
    // shown Cloudflare's raw "daily sending quota" text). No email address on the event.
    await reportHomeError({ message: 'sign-in code email could not be sent', error: sent.error, tags: { route: 'connect/email/start', app: body?.app } });
    return json({ error: CODE_SEND_FAILED, reason: 'send_failed' }, 502);
  }
  await env.AUTH_CODES.put(key, record(now), ttl);
  // `delivery:'logged'` tells the client (dev) the code was console-logged, not emailed (no provider key).
  // Testing convenience: echo the code when UNCONFIGURED + DEV_OTP_ECHO=true (a real SendGrid key never echoes).
  const echo = !emailSendingEnabled(env) && env.DEV_OTP_ECHO === 'true';
  return json({ ok: true, delivery: emailSendingEnabled(env) ? 'sent' : 'logged', ...(echo ? { devCode: code } : {}) });
};
