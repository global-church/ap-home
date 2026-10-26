// The operator directory's admin routes refuse everyone who is not an admin, and never carry a full address where a
// masked one belongs (2026-10-23; gc-estate/docs/operator-workspace.md, "security evaluation").
import { beforeEach, describe, expect, it, vi } from 'vitest';

const A = (n: number) => `0x${String(n).padStart(40, '0')}`;
const OPERATOR = A(900), RYAN = A(1), MALLORY = A(3), HOST = A(10), ORG = A(20);

// The session is "tok:<address>"; anything else does not verify.
vi.mock('@agenticprimitives/connect', async (orig) => ({
  ...(await orig<object>()),
  importJwks: async () => [],
  verifyAgentSession: async (token: string) => (token.startsWith('tok:') ? { ok: true, session: { sub: `eip155:28190:${token.slice(4)}` } } : { ok: false, reason: 'bad' }),
}));
vi.mock('../_lib/server-broker', async (orig) => ({ ...(await orig<object>()), getServer: async () => ({ jwks: {} }), ownIssuer: () => 'https://gcid.test' }));
// On-chain stewardship: only RYAN's grant from the operator org verifies, and only for RYAN.
vi.mock('../_lib/verify-stewardship', () => ({
  verifyStewardship: async (_env: unknown, org: string, person: string, wire: { delegator?: string; delegate?: string } | undefined) =>
    org === OPERATOR && person === RYAN && wire?.delegator === OPERATOR && wire?.delegate === RYAN,
}));

import { onAdminDirectory, onAdminMe, onAdminOrganizations } from './admin';
import { resetOperatorAdminCache } from '../_lib/operator-directory';

function kv(entries: Record<string, unknown>) {
  const m = new Map(Object.entries(entries).map(([k, v]) => [k, JSON.stringify(v)]));
  return {
    get: async (k: string) => m.get(k) ?? null,
    put: async (k: string, v: string) => void m.set(k, v),
    delete: async (k: string) => void m.delete(k),
    list: async ({ prefix }: { prefix: string }) => ({ keys: [...m.keys()].filter((k) => k.startsWith(prefix)).map((name) => ({ name })), list_complete: true }),
  };
}

const ryanLink = { stewardshipDelegation: { delegator: OPERATOR, delegate: RYAN, signature: '0xs', caveats: [] } };
// MALLORY copies Ryan's grant into her own link: it names Ryan, so it must not make her an admin.
const malloryLink = { stewardshipDelegation: { delegator: OPERATOR, delegate: RYAN, signature: '0xs', caveats: [] } };
let doCalls: { url: string; body: Record<string, unknown> }[] = [];
let env: never;

beforeEach(() => {
  resetOperatorAdminCache();
  doCalls = [];
  env = {
    HOME_OPERATOR_ORG: OPERATOR,
    A2A_CUSTODY_URL: 'https://runtime.test',
    AUTH_CODES: kv({
      [`related:${RYAN}:${OPERATOR}`]: ryanLink,
      [`related:${MALLORY}:${OPERATOR}`]: malloryLink,
      [`related:${HOST}:${ORG}`]: { orgName: 'grace.org', displayName: 'Grace Church', requestedBy: 'gather-app', kind: 'org', createdAt: 1 },
    }),
  } as never;
  vi.stubGlobal('fetch', async (url: string, init: RequestInit) => {
    const body = JSON.parse(String(init.body)) as Record<string, unknown>;
    doCalls.push({ url, body });
    if (url.endsWith('/directory.masked')) return new Response(JSON.stringify({ ok: true, contacts: { [HOST]: { masked: 'pa•••r@g•••.org', verifiedAt: 5, source: 'email-sign-in' } } }));
    return new Response(JSON.stringify({ ok: true, email: 'pastor@grace.org' }));
  });
});

const req = (path: string, token: string | null, body?: unknown) =>
  new Request(`https://gcid.test${path}`, { method: body ? 'POST' : 'GET', headers: token ? { authorization: `Bearer ${token}` } : {}, ...(body ? { body: JSON.stringify(body) } : {}) });

describe('who is an admin', () => {
  it('a steward of the operator org, verified on-chain; nobody else', async () => {
    expect(await (await onAdminMe({ request: req('/connect/admin/me', `tok:${RYAN}`), env })).json()).toEqual({ admin: true, operatorOrg: OPERATOR });
    expect(await (await onAdminMe({ request: req('/connect/admin/me', `tok:${MALLORY}`), env })).json()).toEqual({ admin: false });
    expect(await (await onAdminMe({ request: req('/connect/admin/me', 'forged'), env })).json()).toEqual({ admin: false });
  });
});

describe('the organizations list', () => {
  it('refuses no session, a forged one, and a non-admin', async () => {
    expect((await onAdminOrganizations({ request: req('/connect/admin/organizations', null), env })).status).toBe(401);
    expect((await onAdminOrganizations({ request: req('/connect/admin/organizations', 'forged'), env })).status).toBe(401);
    expect((await onAdminOrganizations({ request: req('/connect/admin/organizations', `tok:${MALLORY}`), env })).status).toBe(403);
    expect(doCalls).toHaveLength(0);
  });
  it('for an admin, carries masked addresses only, and asks the directory with the admin’s own session and grant', async () => {
    const r = await onAdminOrganizations({ request: req('/connect/admin/organizations', `tok:${RYAN}`), env });
    const text = await r.text();
    expect(r.status).toBe(200);
    expect(text).toContain('pa•••r@g•••.org');
    expect(text).not.toContain('pastor@grace.org');
    expect(JSON.parse(text).masked).toBe(true);
    expect(doCalls[0]!.body).toMatchObject({ session: `tok:${RYAN}`, stewardship: ryanLink.stewardshipDelegation });
  });
});

describe('All accounts (2026-10-26)', () => {
  it('admin only; every account behind a sign-in, masked', async () => {
    (env as unknown as { AUTH_CODES: { put: (k: string, v: string) => Promise<void> } }).AUTH_CODES.put(
      'facet:email:h1', JSON.stringify([{ agent: `eip155:28190:${HOST}`, assurance: 'verified', ref: 'kv-email' }]),
    );
    expect((await onAdminOrganizations({ request: req('/connect/admin/organizations?app=all-accounts', `tok:${MALLORY}`), env })).status).toBe(403);
    const r = await onAdminOrganizations({ request: req('/connect/admin/organizations?app=all-accounts', `tok:${RYAN}`), env });
    const text = await r.text();
    expect(r.status).toBe(200);
    const j = JSON.parse(text) as { rows: string; orgs: { org: string; orgContact: { email: string } | null }[] };
    expect(j.rows).toBe('accounts');
    expect(j.orgs.find((o) => o.org === HOST)?.orgContact?.email).toBe('pa•••r@g•••.org');
    expect(text).not.toContain('pastor@grace.org');
  });
  it('is not offered without the operator directory', async () => {
    const plain = { ...(env as object), HOME_OPERATOR_ORG: undefined, HOME_ADMINS: RYAN } as never;
    expect((await onAdminOrganizations({ request: req('/connect/admin/organizations?app=all-accounts', `tok:${RYAN}`), env: plain })).status).toBe(400);
  });
});

describe('directory actions', () => {
  it('refuse a non-admin before reaching the directory', async () => {
    for (const action of ['reveal', 'export-request', 'export-approve', 'export-fetch', 'audit', 'import', 'remove-old']) {
      const r = await onAdminDirectory({ request: req('/connect/admin/directory', `tok:${MALLORY}`, { action, account: HOST, id: 'x' }), env });
      expect(r.status, action).toBe(403);
    }
    expect(doCalls).toHaveLength(0);
  });
  it('an admin’s action carries their own session and grant, never one the caller supplied', async () => {
    await onAdminDirectory({ request: req('/connect/admin/directory', `tok:${RYAN}`, { action: 'reveal', account: HOST, session: 'tok:someone-else', stewardship: { forged: true } }), env });
    expect(doCalls[0]!.url).toBe(`https://runtime.test/interactions/${OPERATOR}/directory.reveal`);
    expect(doCalls[0]!.body).toMatchObject({ session: `tok:${RYAN}`, stewardship: ryanLink.stewardshipDelegation, account: HOST });
  });
  it('removing the old directory is recorded first, then its records go (2026-10-26)', async () => {
    const kv = (env as unknown as { AUTH_CODES: { put: (k: string, v: string) => Promise<void>; get: (k: string) => Promise<string | null> } }).AUTH_CODES;
    await kv.put(`contact:${HOST}`, '{"cipher":"x"}');
    await kv.put('contact-views:log', '[]');
    const r = await onAdminDirectory({ request: req('/connect/admin/directory', `tok:${RYAN}`, { action: 'remove-old' }), env });
    expect(r.status).toBe(200);
    expect(doCalls[0]!.url).toBe(`https://runtime.test/interactions/${OPERATOR}/directory.oldRemoved`);
    expect(doCalls[0]!.body).toMatchObject({ count: 1 });
    expect(await kv.get(`contact:${HOST}`)).toBeNull();
    expect(await kv.get('contact-views:log')).toBeNull();
  });
  it('nothing is deleted if the record of it cannot be written', async () => {
    const kv = (env as unknown as { AUTH_CODES: { put: (k: string, v: string) => Promise<void>; get: (k: string) => Promise<string | null> } }).AUTH_CODES;
    await kv.put(`contact:${HOST}`, '{"cipher":"x"}');
    vi.stubGlobal('fetch', async () => new Response(JSON.stringify({ ok: false, error: 'vault down' }), { status: 502 }));
    expect((await onAdminDirectory({ request: req('/connect/admin/directory', `tok:${RYAN}`, { action: 'remove-old' }), env })).status).toBe(502);
    expect(await kv.get(`contact:${HOST}`)).not.toBeNull();
  });
  it('an unknown action is refused', async () => {
    expect((await onAdminDirectory({ request: req('/connect/admin/directory', `tok:${RYAN}`, { action: 'dump-everything' }), env })).status).toBe(400);
  });
});
