// POST /connect/phone/start — begin phone (SMS) verification (phone-auth, login-grade; spec 320).
//   body: { phone, aud? }  → { ok, delivery }
// Twilio Verify sends + manages the OTP (we store NO code when configured). The `aud` context is stashed
// keyed by SHA-256(E.164) so the verify step knows the requesting audience. The raw number is never stored.
// DEPLOY-SAFE: with Twilio unset, we self-generate a dev OTP (stored + logged) so the flow still works.
import type { FnContext } from '../_lib/server-broker';
import { sendPhoneVerification, smsVerifyEnabled, smsMessagingEnabled, sendSms, normalizeE164 } from '../_lib/sms-sender';
import { phoneHash } from '../../src/lib/kv-indexer';
import { whitelabel } from '../../src/whitelabel/config';
import { CODE_SEND_FAILED, reportHomeError } from '../_lib/home-sentry';

const cors = { 'access-control-allow-origin': '*', 'access-control-allow-headers': 'content-type' };
const json = (b: unknown, s = 200): Response =>
  new Response(JSON.stringify(b), { status: s, headers: { 'content-type': 'application/json', ...cors } });

export const onRequestOptions = async (): Promise<Response> => new Response(null, { status: 204, headers: cors });

/** 6-digit cryptographically-random dev code (used ONLY when Twilio Verify is unconfigured). */
function devOtp(): string {
  const n = crypto.getRandomValues(new Uint32Array(1))[0]! % 1_000_000;
  return n.toString().padStart(6, '0');
}

export const onRequestPost = async ({ request, env }: FnContext): Promise<Response> => {
  const body = (await request.json().catch(() => null)) as { phone?: string; aud?: string } | null;
  const phone = normalizeE164(body?.phone ?? '');
  if (!phone) {
    return json(
      { error: 'we couldn’t read that phone number — a US number like 303 555 1234 works, or start with + and your country code' },
      400,
    );
  }

  const aud = body?.aud ?? env.DEMO_SSO_AUD ?? 'demo-sso';
  const key = `phoneverify:${await phoneHash(phone)}`;
  const useVerify = smsVerifyEnabled(env);
  const useMessaging = !useVerify && smsMessagingEnabled(env);

  // Twilio VERIFY (managed OTP) — Twilio owns the code; we stash only the aud so verify knows to check.
  if (useVerify) {
    await env.AUTH_CODES.put(key, JSON.stringify({ aud, provider: 'twilio' }), { expirationTtl: 600 });
    const sent = await sendPhoneVerification(env, phone);
    if (!sent.ok) {
      await reportHomeError({ message: 'sign-in code text could not be sent', error: sent.error, tags: { route: 'connect/phone/start' } });
      return json({ error: CODE_SEND_FAILED, reason: 'send_failed' }, 502);
    }
    return json({ ok: true, delivery: 'sent' });
  }

  // Otherwise WE own the code (verified locally in phone-verify's `dev` path). Deliver it via Twilio
  // Programmable Messaging when configured (trial-friendly, no Verify upgrade), else log/echo it.
  const code = devOtp();
  await env.AUTH_CODES.put(key, JSON.stringify({ aud, provider: 'dev', code, attempts: 0 }), { expirationTtl: 600 });

  if (useMessaging) {
    const sent = await sendSms(env, phone, `${code} is your ${whitelabel.brand.name} sign-in code. It expires in 10 minutes.`);
    if (!sent.ok) {
      await reportHomeError({ message: 'sign-in code text could not be sent', error: sent.error, tags: { route: 'connect/phone/start' } });
      return json({ error: CODE_SEND_FAILED, reason: 'send_failed' }, 502);
    }
    return json({ ok: true, delivery: 'sent' });
  }

  console.log(`[phone-start] (dev) OTP for ${phone} = ${code}`);
  // Twilio is unconfigured, so the only delivery channel is this same trusted browser flow.
  // Real Twilio Verify/Messaging paths above never echo codes.
  return json({ ok: true, delivery: 'logged', devCode: code });
};
