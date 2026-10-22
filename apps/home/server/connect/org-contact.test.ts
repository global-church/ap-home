// An organization's contact email changes only through a code, and only for someone who manages it (2026-10-22).
import { beforeEach, describe, expect, it, vi } from 'vitest';

const sent: Array<{ to: string; subject: string; text: string }> = [];
vi.mock('../_lib/home-sentry', async (orig) => ({ ...(await orig<object>()), reportHomeError: async () => {} }));
vi.mock('../_lib/email-sender', () => ({
  emailSendingEnabled: () => true,
  sendEmail: async (_env: unknown, msg: { to: string; subject: string; text: string }) => {
    sent.push(msg);
    return { ok: true };
  },
}));
// The session is the signed-in person; the token string names them, for the test.
vi.mock('@agenticprimitives/connect', async (orig) => ({
  ...(await orig<object>()),
  importJwks: async () => [],
  verifyAgentSession: async (token: string) => (token === 'bad' ? { ok: false } : { ok: true, session: { sub: `eip155:28190:${token}` } }),
}));
vi.mock('../_lib/server-broker', async (orig) => ({ ...(await orig<object>()), getServer: async () => ({ jwks: {} }), ownIssuer: () => 'https://gcid.test' }));

import { onStart, onVerify } from './org-contact';
import { defaultOrgContact, readContactEmails, recordContactEmail } from '../_lib/contact-directory';

const KEY = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))));
const STEWARD = '0x' + '1'.repeat(40);
const MEMBER = '0x' + '2'.repeat(40);
const ORG = '0x' + '9'.repeat(40);

function kv() {
  const m = new Map<string, string>();
  return { m, get: async (k: string) => m.get(k) ?? null, put: async (k: string, v: string) => void m.set(k, v), delete: async (k: string) => void m.delete(k) };
}
let store: ReturnType<typeof kv>;
let env: never;
beforeEach(() => {
  sent.length = 0;
  store = kv();
  store.m.set(`related:${STEWARD}:${ORG}`, JSON.stringify({ orgName: 'grace.org', displayName: 'Grace Church', kind: 'org' }));
  store.m.set(`related:${MEMBER}:${ORG}`, JSON.stringify({ orgName: 'grace.org', kind: 'org', relationship: 'member' }));
  env = { AUTH_CODES: store, CONTACT_DIRECTORY_KEY: KEY } as never;
  vi.spyOn(console, 'info').mockImplementation(() => {});
});

const post = (fn: typeof onStart, who: string, body: Record<string, unknown>) =>
  fn({ request: new Request('https://gcid.test/connect/org-contact', { method: 'POST', headers: { authorization: `Bearer ${who}` }, body: JSON.stringify(body) }), env } as never);
const codeSent = () => sent[sent.length - 1]!.subject.slice(0, 6);

describe('changing an organization’s contact email', () => {
  it('a manager gets a code at the new address, and the right code makes it the organization’s contact', async () => {
    expect((await post(onStart, STEWARD, { org: ORG, email: 'Office@Grace.org' })).status).toBe(200);
    expect(sent[0]!.to).toBe('office@grace.org');
    expect(sent[0]!.text).toContain('Grace Church');
    const r = await post(onVerify, STEWARD, { org: ORG, email: 'office@grace.org', otp: codeSent() });
    expect(r.status).toBe(200);
    const got = (await readContactEmails(env, [ORG])).get(ORG);
    expect(got?.email).toBe('office@grace.org');
    expect(got?.source).toBe(`org-verified:${STEWARD}`);
  });

  it('a member, someone with no link, or no session is refused', async () => {
    expect((await post(onStart, MEMBER, { org: ORG, email: 'x@y.org' })).status).toBe(403);
    expect((await post(onStart, '0x' + '3'.repeat(40), { org: ORG, email: 'x@y.org' })).status).toBe(403);
    expect((await post(onStart, 'bad', { org: ORG, email: 'x@y.org' })).status).toBe(401);
    expect(sent).toHaveLength(0);
  });

  it('a wrong code changes nothing, and five wrong tries end the code', async () => {
    await post(onStart, STEWARD, { org: ORG, email: 'office@grace.org' });
    const wrong = codeSent() === '000000' ? '111111' : '000000';
    for (let i = 0; i < 4; i++) expect((await post(onVerify, STEWARD, { org: ORG, email: 'office@grace.org', otp: wrong })).status).toBe(400);
    expect((await post(onVerify, STEWARD, { org: ORG, email: 'office@grace.org', otp: wrong })).status).toBe(429);
    expect((await post(onVerify, STEWARD, { org: ORG, email: 'office@grace.org', otp: codeSent() })).status).toBe(400); // gone
    expect((await readContactEmails(env, [ORG])).size).toBe(0);
  });

  it('a code for one address does not confirm another', async () => {
    await post(onStart, STEWARD, { org: ORG, email: 'office@grace.org' });
    expect((await post(onVerify, STEWARD, { org: ORG, email: 'other@grace.org', otp: codeSent() })).status).toBe(400);
  });
});

describe('the default: the creator’s email', () => {
  it('is copied to a new organization that has no contact, and never over one it has', async () => {
    await recordContactEmail(env, STEWARD, 'pastor@grace.org', 'email-sign-in');
    expect(await defaultOrgContact(env, STEWARD, ORG)).toBe(true);
    expect((await readContactEmails(env, [ORG])).get(ORG)?.email).toBe('pastor@grace.org');
    await recordContactEmail(env, ORG, 'office@grace.org', 'org-verified:x');
    expect(await defaultOrgContact(env, STEWARD, ORG)).toBe(false);
    expect((await readContactEmails(env, [ORG])).get(ORG)?.email).toBe('office@grace.org');
  });
});
