import { beforeEach, describe, expect, it } from 'vitest';
import { directoryScopeExact, handleDirectoryOp, type DirectoryCtx, type Wire } from '../src/operator-directory-ops';
import { AUDIT_LOG, sha256Hex } from '../src/operator-directory';

const A = (n: number) => `0x${String(n).padStart(40, '0')}`;
const OPERATOR = A(900), RYAN = A(1), PAUL = A(2), MALLORY = A(3), HOST = A(10), CHURCH = A(20), SERVICE = A(777);

const wire = (delegator: string, delegate: string): Wire => ({ delegator, delegate, signature: '0xsig', caveats: [], salt: 1 });
const DIRECTORY_GRANT = wire(OPERATOR, SERVICE);

/** Sessions are "session:<account>:<email or ->"; stewardship is held by RYAN and PAUL for OPERATOR, HOST for CHURCH. */
function harness() {
  const vault = new Map<string, unknown>();
  let grant: Wire | undefined;
  let t = 1_000_000;
  let n = 0;
  const stewards: Record<string, string[]> = { [OPERATOR]: [RYAN, PAUL], [CHURCH]: [HOST] };
  const ctx: DirectoryCtx = {
    principal: OPERATOR,
    now: () => t,
    newId: () => `e${++n}`,
    async verifySession(s) {
      const [kind, sa, email] = s.split(':');
      if (kind !== 'session' || !sa) return { ok: false, error: 'invalid session' };
      return { ok: true, sa, ...(email && email !== '-' ? { principal: { kind: 'oidc', id: `email#${await sha256Hex(email)}` } } : {}) };
    },
    async isSteward(org, sa, w) { return !!w && w.delegator === org && w.delegate === sa && (stewards[org] ?? []).includes(sa); },
    async grantSignatureOk(w) { return w.signature === '0xsig'; },
    recordScopes(w) { return (w as Wire & { scopes?: { resources: string[]; ops: string[] }[] }).scopes ?? null; },
    expectedDelegate: async () => SERVICE,
    async getGrant() { return grant; },
    async setGrant(w) { grant = w; },
    async read(_g, r) { return vault.get(r) ?? null; },
    async readMany(_g, rs) { return Object.fromEntries(rs.map((r) => [r, vault.get(r) ?? null])); },
    async write(_g, r, d) { vault.set(r, d); },
    serial: (_k, w) => w(),
  };
  return { ctx, vault, enable: () => { grant = DIRECTORY_GRANT; }, tick: (ms: number) => { t += ms; } };
}

const as = (sa: string, email = '-', org = OPERATOR) => ({ session: `session:${sa}:${email}`, stewardship: wire(org, sa) });
const call = (h: ReturnType<typeof harness>, op: string, body: Record<string, unknown>) => handleDirectoryOp(h.ctx, op, body);
const audit = (h: ReturnType<typeof harness>) => (h.vault.get(AUDIT_LOG) as { kind: string; by: string }[] | undefined) ?? [];

let h: ReturnType<typeof harness>;
beforeEach(() => { h = harness(); h.enable(); });

describe('recording a person’s email', () => {
  it('records the address their own session signed in with', async () => {
    expect((await call(h, 'directory.record', { session: `session:${HOST}:pastor@grace.org`, email: 'Pastor@Grace.org' })).status).toBe(200);
    expect(h.vault.get(`contact:${HOST}`)).toMatchObject({ email: 'pastor@grace.org', source: 'email-sign-in' });
  });
  it('refuses any other address, and a session that did not sign in by email', async () => {
    expect((await call(h, 'directory.record', { session: `session:${HOST}:pastor@grace.org`, email: 'boss@grace.org' })).status).toBe(403);
    expect((await call(h, 'directory.record', { session: `session:${HOST}:-`, email: 'pastor@grace.org' })).status).toBe(403);
    expect((await call(h, 'directory.record', { session: 'forged', email: 'pastor@grace.org' })).status).toBe(401);
    expect(h.vault.has(`contact:${HOST}`)).toBe(false);
  });
});

describe('an organization’s contact', () => {
  it('defaults to its creator’s verified email, copied, never over an existing one', async () => {
    await call(h, 'directory.record', { session: `session:${HOST}:pastor@grace.org`, email: 'pastor@grace.org' });
    const r = await call(h, 'directory.defaultOrg', { ...as(HOST, 'pastor@grace.org', CHURCH), org: CHURCH });
    expect(r.body).toMatchObject({ ok: true, recorded: true });
    expect(h.vault.get(`contact:${CHURCH}`)).toMatchObject({ email: 'pastor@grace.org', source: `org-default:${HOST}` });
    await call(h, 'directory.recordOrg', { ...as(HOST, '-', CHURCH), org: CHURCH, email: 'office@grace.org' });
    expect((await call(h, 'directory.defaultOrg', { ...as(HOST, '-', CHURCH), org: CHURCH })).body).toMatchObject({ recorded: false });
    expect(h.vault.get(`contact:${CHURCH}`)).toMatchObject({ email: 'office@grace.org' });
  });
  it('only someone who manages the org may set it', async () => {
    expect((await call(h, 'directory.recordOrg', { ...as(MALLORY, '-', CHURCH), org: CHURCH, email: 'evil@x.org' })).status).toBe(403);
  });
});

describe('admins only', () => {
  it('refuses a non-admin, and an admin presenting someone else’s grant', async () => {
    for (const op of ['directory.masked', 'directory.reveal', 'directory.audit', 'export.request', 'export.list', 'directory.import']) {
      expect((await call(h, op, { ...as(MALLORY), account: HOST, accounts: [HOST] })).status, op).toBe(403);
      expect((await call(h, op, { session: `session:${MALLORY}:-`, stewardship: wire(OPERATOR, RYAN), account: HOST, accounts: [HOST] })).status, op).toBe(403);
    }
  });
  it('the list is masked and its viewing is recorded', async () => {
    await call(h, 'directory.record', { session: `session:${HOST}:pastor@grace.org`, email: 'pastor@grace.org' });
    const r = await call(h, 'directory.masked', { ...as(RYAN), accounts: [HOST, CHURCH] });
    expect(JSON.stringify(r.body)).not.toContain('pastor@grace.org');
    expect((r.body.contacts as Record<string, { masked: string }>)[HOST]!.masked).toBe('pa•••r@g•••.org');
    expect(audit(h).at(-1)).toMatchObject({ kind: 'list', by: RYAN });
  });
  it('a reveal returns one address and is recorded', async () => {
    await call(h, 'directory.record', { session: `session:${HOST}:pastor@grace.org`, email: 'pastor@grace.org' });
    expect((await call(h, 'directory.reveal', { ...as(PAUL), account: HOST })).body).toMatchObject({ email: 'pastor@grace.org' });
    expect(audit(h).at(-1)).toMatchObject({ kind: 'reveal', by: PAUL });
  });
  it('enabling requires exactly the directory scope, the right delegate and a valid signature', async () => {
    const good = { ...wire(OPERATOR, SERVICE), scopes: [{ resources: ['vault:contact:*', 'vault:directory.audit:*', 'vault:export:*'], ops: ['read', 'write'] }] };
    expect((await call(h, 'directory.enable', { ...as(RYAN), delegation: { ...good, delegate: MALLORY } })).status).toBe(403);
    expect((await call(h, 'directory.enable', { ...as(RYAN), delegation: { ...good, scopes: [{ resources: ['vault:contact:*'], ops: ['read', 'write'] }] } })).status).toBe(403);
    expect((await call(h, 'directory.enable', { ...as(RYAN), delegation: { ...good, signature: '0xbad' } })).status).toBe(403);
    expect((await call(h, 'directory.enable', { ...as(RYAN), delegation: good })).status).toBe(200);
  });
});

describe('two-admin export, end to end', () => {
  beforeEach(async () => {
    await call(h, 'directory.record', { session: `session:${HOST}:pastor@grace.org`, email: 'pastor@grace.org' });
  });
  it('request -> a different admin approves -> the requester downloads once', async () => {
    const req = await call(h, 'export.request', { ...as(RYAN), app: 'gather-app', accounts: [HOST, CHURCH] });
    const id = (req.body.request as { id: string }).id;
    expect((await call(h, 'export.fetch', { ...as(RYAN), id })).status).toBe(403);       // not approved
    expect((await call(h, 'export.approve', { ...as(RYAN), id })).status).toBe(403);     // own request
    expect((await call(h, 'export.approve', { ...as(PAUL), id })).status).toBe(200);
    expect((await call(h, 'export.fetch', { ...as(PAUL), id })).status).toBe(403);       // not the requester
    const got = await call(h, 'export.fetch', { ...as(RYAN), id });
    expect(got.body.rows).toEqual([{ account: HOST, email: 'pastor@grace.org', verifiedAt: expect.any(Number) }, { account: CHURCH, email: null, verifiedAt: null }]);
    expect((await call(h, 'export.fetch', { ...as(RYAN), id })).status).toBe(403);       // once
    expect(audit(h).map((e) => e.kind).filter((k) => k.startsWith('export'))).toEqual(['export-request', 'export-approve', 'export-fetch']);
  });
  it('a denied or expired request never downloads', async () => {
    const id = ((await call(h, 'export.request', { ...as(RYAN), app: 'gather-app', accounts: [HOST] })).body.request as { id: string }).id;
    await call(h, 'export.deny', { ...as(PAUL), id });
    expect((await call(h, 'export.fetch', { ...as(RYAN), id })).status).toBe(403);
    const id2 = ((await call(h, 'export.request', { ...as(RYAN), app: 'gather-app', accounts: [HOST] })).body.request as { id: string }).id;
    await call(h, 'export.approve', { ...as(PAUL), id: id2 });
    h.tick(31 * 60 * 1000);
    expect((await call(h, 'export.fetch', { ...as(RYAN), id: id2 })).body.error).toBe('this export is expired');
  });
  it('the request list never carries the accounts', async () => {
    await call(h, 'export.request', { ...as(RYAN), app: 'gather-app', accounts: [HOST] });
    const list = await call(h, 'export.list', as(PAUL));
    expect(JSON.stringify(list.body)).not.toContain(HOST);
  });
});

describe('scope check', () => {
  it('exactly the three directory record families, read and write', () => {
    expect(directoryScopeExact([{ resources: ['vault:contact:*', 'vault:directory.audit:*', 'vault:export:*'], ops: ['read', 'write'] }])).toBe(true);
    expect(directoryScopeExact([{ resources: ['vault:contact:*', 'vault:directory.audit:*', 'vault:export:*', 'vault:inbox.data'], ops: ['read', 'write'] }])).toBe(false);
    expect(directoryScopeExact([{ resources: ['vault:contact:*', 'vault:directory.audit:*', 'vault:export:*'], ops: ['write'] }])).toBe(false);
    expect(directoryScopeExact(null)).toBe(false);
  });
});
