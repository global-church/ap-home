// POST /connect/app-invite/email — a registered relying app asks Home to SendGrid an invite
// link that already exists on that app (Gather27 host intake, etc.).
//
//   body: { email, returnUrl, app? }  → { ok, delivery }
//
// This is NOT an org-membership invite. Org membership stays on /connect/org-invite/email
// (steward + member-access grant). Here Home is only the mailer: SendGrid key never leaves Home,
// and the join URL origin must be a registered redirect for the calling app.
import { sendEmail, inviteEmail, emailSendingEnabled } from '../_lib/email-sender';
import { resolveOrigin, type FnContext } from '../_lib/server-broker';
import { resolveClient } from '../_lib/oidc-registry';
import { whitelabel } from '../../src/whitelabel/config';
import { callerFromInviteAuth } from './org-invite';

const cors = { 'access-control-allow-origin': '*', 'access-control-allow-headers': 'content-type, authorization' };
const json = (b: unknown, s = 200): Response =>
  new Response(JSON.stringify(b), { status: s, headers: { 'content-type': 'application/json', ...cors } });

export const onRequestOptions = async (): Promise<Response> => new Response(null, { status: 204, headers: cors });

const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

export const onRequestPost = async ({ request, env }: FnContext): Promise<Response> => {
  const body = (await request.json().catch(() => null)) as
    | { email?: string; returnUrl?: string; app?: string; name?: string }
    | null;
  const email = (body?.email ?? '').trim().toLowerCase();
  const rawReturn = (body?.returnUrl ?? '').trim();
  if (!EMAIL_RE.test(email) || !rawReturn) return json({ error: 'email + returnUrl required' }, 400);

  const caller = await callerFromInviteAuth(env, request);
  if (!caller) return json({ error: 'sign in at Home to send an invite' }, 401);

  const clientId = caller.clientId ?? (typeof body?.app === 'string' ? body.app : null);
  if (!clientId) return json({ error: 'app (client_id) required when sending from a Home session' }, 400);
  const client = await resolveClient(env, clientId);
  if (!client) return json({ error: 'unknown app' }, 400);

  let url: URL;
  try { url = new URL(rawReturn); } catch { return json({ error: 'returnUrl is not a URL' }, 400); }
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && (url.hostname === 'localhost' || url.hostname === '127.0.0.1'))) {
    return json({ error: 'returnUrl must be https' }, 400);
  }
  const origins = new Set(client.redirect_uris.map((u) => { try { return new URL(u).origin; } catch { return ''; } }));
  if (!origins.has(url.origin)) return json({ error: 'returnUrl must be an origin registered for your app' }, 400);

  const appName = client.name ?? clientId;
  const orgName = (body?.name ?? '').trim() || appName;
  const joinUrl = url.toString().slice(0, 500);
  // A reply to the invite belongs to the app that invited them (its own inbox), not to Home's no-reply sender.
  const replyTo = (client as { replyTo?: string }).replyTo;
  const sent = await sendEmail(env, { ...inviteEmail(email, joinUrl, orgName, whitelabel.brand.name, appName), ...(replyTo ? { replyTo } : {}) });
  if (!sent.ok) return json({ error: `could not send invite: ${sent.error}` }, 502);
  return json({
    ok: true,
    delivery: emailSendingEnabled(env) ? 'sent' : 'logged',
    joinUrl,
    appName,
    issuer: resolveOrigin(request, env),
  });
};
