// Co-management is granted only by someone who manages the org, only as a real stewardship grant, and accepted only by
// the person named in it (2026-10-23).
import { beforeEach, describe, expect, it, vi } from 'vitest';

const A = (n: number) => `0x${String(n).padStart(40, '0')}`;
const ORG = A(900), RYAN = A(1), PAUL = A(2), MALLORY = A(3), PAUL_KEY = A(52);
let revoked = false;

vi.mock('./org-invite', () => ({
  // The bearer is "tok:<address>"; RYAN manages ORG.
  callerFromInviteAuth: async (_e: unknown, r: Request) => {
    const t = (r.headers.get('authorization') ?? '').replace('Bearer ', '');
    return t.startsWith('tok:') ? { person: t.slice(4) } : null;
  },
  stewardControl: async (_e: unknown, r: Request, org: string) => {
    const t = (r.headers.get('authorization') ?? '').replace('Bearer ', '');
    return t === `tok:${RYAN}` && org === ORG ? { person: RYAN, stewardship: {}, session: t } : null;
  },
}));
vi.mock('../_lib/verify-stewardship', () => ({
  verifyStewardship: async (_e: unknown, org: string, person: string, wire: { delegator?: string; delegate?: string } | undefined) =>
    !revoked && org === ORG && wire?.delegator === ORG && wire?.delegate === person,
}));
vi.mock('viem', async (orig) => ({
  ...(await orig<object>()),
  createPublicClient: () => ({ readContract: async ({ address, args }: { address: string; args: string[] }) => address === PAUL && args[0] === PAUL_KEY }),
}));

import { onCoManagerGet, onCoManagerPost } from './co-manager';

function kv() {
  const m = new Map<string, string>();
  return {
    m,
    get: async (k: string) => m.get(k) ?? null,
    put: async (k: string, v: string) => void m.set(k, v),
    delete: async (k: string) => void m.delete(k),
    list: async ({ prefix }: { prefix: string }) => ({ keys: [...m.keys()].filter((k) => k.startsWith(prefix)).map((name) => ({ name })), list_complete: true }),
  };
}
let store: ReturnType<typeof kv>;
let env: never;
beforeEach(() => { revoked = false; store = kv(); env = { AUTH_CODES: store } as never; });

const post = (token: string, body: unknown) =>
  onCoManagerPost({ request: new Request('https://gcid.test/connect/co-manager', { method: 'POST', headers: { authorization: `Bearer ${token}` }, body: JSON.stringify(body) }), env });
const grant = (person: string) => ({ delegator: ORG, delegate: person, signature: '0xs', caveats: [], salt: '1' });

describe('offering co-management', () => {
  it('only a manager can offer, and only a real stewardship grant for that person', async () => {
    expect((await post(`tok:${MALLORY}`, { action: 'offer', org: ORG, person: PAUL, delegation: grant(PAUL) })).status).toBe(403);
    expect((await post(`tok:${RYAN}`, { action: 'offer', org: ORG, person: PAUL, delegation: grant(MALLORY) })).status).toBe(400);
    expect((await post(`tok:${RYAN}`, { action: 'offer', org: ORG, person: PAUL, delegation: grant(PAUL) })).status).toBe(200);
  });
});

describe('accepting', () => {
  beforeEach(async () => { await post(`tok:${RYAN}`, { action: 'offer', org: ORG, person: PAUL, delegation: grant(PAUL) }); });

  it('only the named person can accept; it writes their own steward link and drops the grant from the offer', async () => {
    expect((await post(`tok:${MALLORY}`, { action: 'accept', org: ORG })).status).toBe(404);
    expect((await post(`tok:${PAUL}`, { action: 'accept', org: ORG, custodian: PAUL_KEY })).status).toBe(200);
    const link = JSON.parse(store.m.get(`related:${PAUL}:${ORG}`)!);
    expect(link).toMatchObject({ relationship: 'steward', stewardshipDelegation: grant(PAUL) });
    const offer = JSON.parse(store.m.get(`co-manager:${PAUL}:${ORG}`)!);
    expect(offer.delegation).toBeUndefined();
    expect(offer.custodian).toBe(PAUL_KEY);
    expect((await post(`tok:${PAUL}`, { action: 'accept', org: ORG })).status).toBe(404); // once
  });
  it('a revoked offer is refused at acceptance', async () => {
    revoked = true;
    expect((await post(`tok:${PAUL}`, { action: 'accept', org: ORG })).status).toBe(409);
    expect(store.m.has(`related:${PAUL}:${ORG}`)).toBe(false);
  });
  it('a custodian that does not control the person’s account is refused', async () => {
    expect((await post(`tok:${PAUL}`, { action: 'accept', org: ORG, custodian: A(66) })).status).toBe(400);
  });
  it('a workspace stays a workspace under its governor when the co-manager accepts (2026-10-26)', async () => {
    const GOVERNOR = A(901);
    store.m.set(`related:${RYAN}:${ORG}`, JSON.stringify({ kind: 'workspace', parent: GOVERNOR, orgName: 'gcid-operations.workspace' }));
    await post(`tok:${RYAN}`, { action: 'offer', org: ORG, person: PAUL, delegation: grant(PAUL) });
    expect((await post(`tok:${PAUL}`, { action: 'accept', org: ORG })).status).toBe(200);
    expect(JSON.parse(store.m.get(`related:${PAUL}:${ORG}`)!)).toMatchObject({ kind: 'workspace', parent: GOVERNOR, relationship: 'steward' });
  });
  it('the manager’s list never returns the grant', async () => {
    const r = await onCoManagerGet({ request: new Request(`https://gcid.test/connect/co-manager?org=${ORG}`, { headers: { authorization: `Bearer tok:${RYAN}` } }), env });
    const j = (await r.json()) as { offers: Record<string, unknown>[] };
    expect(j.offers[0]!.delegation).toBeUndefined();
    expect((await onCoManagerGet({ request: new Request(`https://gcid.test/connect/co-manager?org=${ORG}`, { headers: { authorization: `Bearer tok:${MALLORY}` } }), env })).status).toBe(403);
  });
});
