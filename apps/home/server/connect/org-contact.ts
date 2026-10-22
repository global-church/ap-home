// THE ORGANIZATION'S CONTACT EMAIL (Global.Church, 2026-10-22; Paul's design).
//
// An organization has its own contact email, not only the people who manage it. It starts as the creator's
// verified email (set when the org is created: onboarding.ts writes it into `org.profile`, grant.ts copies the
// operator record). After that, the ONLY way to change it is to prove the new inbox with a code:
//
//   POST /connect/org-contact/start   { org, email }       → emails a 6-digit code to `email`
//   POST /connect/org-contact/verify  { org, email, otp }  → checks it, keeps the operator copy, says "verified"
//
// Both need the Bearer session of a person who MANAGES the org (their related link to it, not a membership).
// On "verified" the page writes `contactEmail` into the org's own `org.profile` over the person's stewardship
// delegation (the record lives in the org's vault, ADR-0055); the operator copy (contact-directory.ts, AAD = the
// org's address) is what GCID Admin shows. The code is keyed by org AND email, separate from sign-in codes, so
// confirming an address never touches anyone's sign-in.
import { importJwks, verifyAgentSession } from '@agenticprimitives/connect';
import { getServer, ownIssuer, type Env, type FnContext } from '../_lib/server-broker';
import { sendEmail, emailSendingEnabled } from '../_lib/email-sender';
import { emailHash } from '../../src/lib/kv-indexer';
import { whitelabel } from '../../src/whitelabel/config';
import { accountAddress, recordContactEmail } from '../_lib/contact-directory';
import { reportHomeError } from '../_lib/home-sentry';

const cors = { 'access-control-allow-origin': '*', 'access-control-allow-headers': 'content-type, authorization' };
const json = (b: unknown, s = 200): Response =>
  new Response(JSON.stringify(b), { status: s, headers: { 'content-type': 'application/json', 'cache-control': 'no-store', ...cors } });

export const onRequestOptions = async (): Promise<Response> => new Response(null, { status: 204, headers: cors });

const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
const ADDRESS = /^0x[0-9a-f]{40}$/;
const MAX_ATTEMPTS = 5;
const CODE_TTL_S = 600;
const RESEND_GAP_MS = 30_000;

const otpKey = async (org: string, email: string) => `orgcontactotp:${org}:${await emailHash(email)}`;

function esc(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);
}

/** The signed-in person, and the organization they manage — or the refusal. */
async function stewardOf(request: Request, env: Env, orgRaw: unknown): Promise<{ ok: true; person: string; org: string; orgName: string } | { ok: false; res: Response }> {
  const auth = request.headers.get('authorization') ?? '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  if (!token) return { ok: false, res: json({ error: 'sign in first' }, 401) };
  const { jwks } = await getServer(env);
  const v = await verifyAgentSession(token, { keys: await importJwks(jwks), expectedAud: env.DEMO_SSO_AUD ?? 'demo-sso', expectedIss: ownIssuer(request, env) });
  const person = v.ok ? accountAddress(String(v.session.sub)) : null;
  if (!person) return { ok: false, res: json({ error: 'sign in first' }, 401) };
  const org = String(orgRaw ?? '').trim().toLowerCase();
  if (!ADDRESS.test(org)) return { ok: false, res: json({ error: 'org must be an organization address' }, 400) };
  type Link = { relationship?: string; status?: string; orgName?: string; displayName?: string };
  const raw = await env.AUTH_CODES.get(`related:${person}:${org}`);
  const link = ((): Link | null => {
    try {
      return raw ? (JSON.parse(raw) as Link) : null;
    } catch {
      return null;
    }
  })();
  // A member can see an organization; only someone who manages it can change how it is reached.
  if (!link || (link.relationship ?? '').toLowerCase() === 'member' || link.status === 'deleted') {
    return { ok: false, res: json({ error: 'only someone who manages this organization can change its contact email' }, 403) };
  }
  return { ok: true, person, org, orgName: link.displayName || link.orgName || 'your organization' };
}

function codeEmail(to: string, code: string, orgName: string, brand: string) {
  return {
    to,
    subject: `${code} confirms the contact email for ${orgName}`,
    text: `Your code is ${code}. Enter it in ${brand} to make ${to} the contact email for ${orgName}. It expires in 10 minutes.\n\nIf you didn't ask for this, you can ignore this email.`,
    html: `<div style="font-family:system-ui,sans-serif;max-width:480px;margin:0 auto;padding:24px;color:#1c1917">
      <p style="font-size:15px">Enter this code in ${esc(brand)} to make <b>${esc(to)}</b> the contact email for <b>${esc(orgName)}</b>:</p>
      <p style="font-size:30px;font-weight:700;letter-spacing:4px;margin:8px 0">${code}</p>
      <p style="font-size:13px;color:#6b7280">Expires in 10 minutes. If you didn't ask for this, you can ignore this email.</p></div>`,
  };
}

export const onStart = async ({ request, env }: FnContext): Promise<Response> => {
  const body = (await request.json().catch(() => null)) as { org?: string; email?: string } | null;
  const g = await stewardOf(request, env, body?.org);
  if (!g.ok) return g.res;
  const email = (body?.email ?? '').trim().toLowerCase();
  if (!EMAIL_RE.test(email) || email.length > 254) return json({ error: 'a valid email is required' }, 400);
  const key = await otpKey(g.org, email);
  const prev = await env.AUTH_CODES.get(key).then((r) => (r ? (JSON.parse(r) as { code: string; attempts: number; issuedAt: number; sentAt: number }) : null)).catch(() => null);
  const now = Date.now();
  if (prev?.sentAt && now - prev.sentAt < RESEND_GAP_MS) return json({ ok: true, repeated: true });
  // One code per (org, email) while it is valid, as at sign-in: a resend repeats it and keeps its attempts.
  const code = prev?.code ?? String(crypto.getRandomValues(new Uint32Array(1))[0]! % 1_000_000).padStart(6, '0');
  const issuedAt = prev?.issuedAt ?? now;
  const ttl = { expirationTtl: Math.max(60, CODE_TTL_S - Math.floor((now - issuedAt) / 1000)) };
  const record = (sentAt: number) => JSON.stringify({ code, attempts: prev?.attempts ?? 0, issuedAt, sentAt, by: g.person });
  await env.AUTH_CODES.put(key, record(prev?.sentAt ?? 0), ttl);
  const sent = await sendEmail(env, codeEmail(email, code, g.orgName, whitelabel.brand.name));
  if (!sent.ok) {
    await reportHomeError({ message: 'org contact code email could not be sent', error: sent.error, tags: { route: 'connect/org-contact/start' } });
    return json({ error: 'We couldn’t send the code. Check the address and try again.' }, 502);
  }
  await env.AUTH_CODES.put(key, record(now), ttl);
  return json({ ok: true, delivery: emailSendingEnabled(env) ? 'sent' : 'logged' });
};

export const onVerify = async ({ request, env }: FnContext): Promise<Response> => {
  const body = (await request.json().catch(() => null)) as { org?: string; email?: string; otp?: string } | null;
  const g = await stewardOf(request, env, body?.org);
  if (!g.ok) return g.res;
  const email = (body?.email ?? '').trim().toLowerCase();
  const otp = (body?.otp ?? '').trim();
  if (!EMAIL_RE.test(email) || !/^\d{6}$/.test(otp)) return json({ error: 'email and the 6-digit code are required' }, 400);
  const key = await otpKey(g.org, email);
  const raw = await env.AUTH_CODES.get(key);
  if (!raw) return json({ error: 'That code has expired. Send a new one.' }, 400);
  const rec = JSON.parse(raw) as { code: string; attempts: number; issuedAt: number; sentAt: number };
  if (rec.code !== otp) {
    const attempts = (rec.attempts ?? 0) + 1;
    if (attempts >= MAX_ATTEMPTS) {
      await env.AUTH_CODES.delete(key);
      return json({ error: 'Too many tries. Send a new code.' }, 429);
    }
    await env.AUTH_CODES.put(key, JSON.stringify({ ...rec, attempts }), { expirationTtl: Math.max(60, CODE_TTL_S - Math.floor((Date.now() - rec.issuedAt) / 1000)) });
    return json({ error: 'That code isn’t right.' }, 400);
  }
  await env.AUTH_CODES.delete(key);
  const verifiedAt = Date.now();
  await recordContactEmail(env, g.org, email, `org-verified:${g.person}`, verifiedAt);
  console.info('[org-contact] verified', { org: g.org, by: g.person, at: new Date(verifiedAt).toISOString() });
  return json({ ok: true, email, verifiedAt });
};
