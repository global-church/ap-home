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
  // HOST also "stewards" its own account: a self-signed grant, which the DO must not treat as an organization.
  const stewards: Record<string, string[]> = { [OPERATOR]: [RYAN, PAUL], [CHURCH]: [HOST], [HOST]: [HOST] };
  let duringRead: (() => Promise<void>) | null = null;
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
    async readMany(_g, rs) { const hook = duringRead; duringRead = null; if (hook) await hook(); return Object.fromEntries(rs.map((r) => [r, vault.get(r) ?? null])); },
    async write(_g, r, d) { vault.set(r, d); },
    serial: (_k, w) => w(),
    // A fake seal: reversible, bound to the account, and never the plain email.
    async seal(account, email) { return 's1.' + btoa(`${account}|${email}`); },
    async listContacts() { return [...vault.keys()].filter((k) => k.startsWith('contact:')).map((k) => k.slice('contact:'.length)); },
    async open(account, sealed) { const [a, e] = atob(sealed.slice(3)).split('|'); if (a !== account) throw new Error('bound to another record'); return e!; },
  };
  return { ctx, vault, enable: () => { grant = DIRECTORY_GRANT; }, tick: (ms: number) => { t += ms; }, whileReading: (fn: () => Promise<void>) => { duringRead = fn; } };
}

const as = (sa: string, email = '-', org = OPERATOR) => ({ session: `session:${sa}:${email}`, stewardship: wire(org, sa) });
const call = (h: ReturnType<typeof harness>, op: string, body: Record<string, unknown>) => handleDirectoryOp(h.ctx, op, body);
const audit = (h: ReturnType<typeof harness>) => (h.vault.get(AUDIT_LOG) as { kind: string; by: string }[] | undefined) ?? [];

let h: ReturnType<typeof harness>;
beforeEach(() => { h = harness(); h.enable(); });

describe('recording a person’s email', () => {
  it('records the address their own session signed in with', async () => {
    expect((await call(h, 'directory.record', { session: `session:${HOST}:pastor@grace.org`, email: 'Pastor@Grace.org' })).status).toBe(200);
    expect(h.vault.get(`contact:${HOST}`)).toMatchObject({ v: 3, masked: 'pa•••r@g•••.org', source: 'email-sign-in' });
    expect(JSON.stringify(h.vault.get(`contact:${HOST}`))).not.toContain('pastor@grace.org');
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
    expect(h.vault.get(`contact:${CHURCH}`)).toMatchObject({ v: 3, masked: 'pa•••r@g•••.org', source: 'org-default' });
    // Who set it is in the audit log, not on the record (it carries no address).
    expect(JSON.stringify(h.vault.get(`contact:${CHURCH}`))).not.toContain(HOST);
    expect(audit(h).at(-1)).toMatchObject({ kind: 'org-contact', by: HOST });
    await call(h, 'directory.recordOrg', { ...as(HOST, 'office@grace.org', CHURCH), org: CHURCH, email: 'office@grace.org' });
    expect((await call(h, 'directory.defaultOrg', { ...as(HOST, '-', CHURCH), org: CHURCH })).body).toMatchObject({ recorded: false });
    expect(h.vault.get(`contact:${CHURCH}`)).toMatchObject({ masked: 'of•••e@g•••.org', source: 'org-verified' });
  });
  it('only someone who manages the org may set it', async () => {
    expect((await call(h, 'directory.recordOrg', { ...as(MALLORY, 'evil@x.org', CHURCH), org: CHURCH, email: 'evil@x.org' })).status).toBe(403);
  });
  it('a manager cannot set an address that was not verified with a code (security review #5)', async () => {
    // HOST's own session (signed in as pastor@) calling directly with another address: refused.
    expect((await call(h, 'directory.recordOrg', { ...as(HOST, 'pastor@grace.org', CHURCH), org: CHURCH, email: 'anything@else.org' })).status).toBe(403);
    expect((await call(h, 'directory.recordOrg', { ...as(HOST, '-', CHURCH), org: CHURCH, email: 'anything@else.org' })).status).toBe(403);
    expect(h.vault.has(`contact:${CHURCH}`)).toBe(false);
  });
  it('an account is not its own organization, even with a self-signed grant (security review #5)', async () => {
    for (const op of ['directory.recordOrg', 'directory.defaultOrg']) {
      expect((await call(h, op, { ...as(HOST, 'fake@x.org', HOST), org: HOST, email: 'fake@x.org' })).status, op).toBe(400);
    }
    expect(h.vault.has(`contact:${HOST}`)).toBe(false);
  });
});

describe('admins only', () => {
  it('refuses a non-admin, and an admin presenting someone else’s grant', async () => {
    for (const op of ['directory.masked', 'directory.reveal', 'directory.audit', 'export.request', 'export.list', 'directory.import', 'directory.oldRemoved']) {
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
  it('removing the old directory is recorded with who and how many', async () => {
    expect((await call(h, 'directory.oldRemoved', { ...as(RYAN), count: 309 })).status).toBe(200);
    expect(audit(h).at(-1)).toMatchObject({ kind: 'old-removed', by: RYAN, accounts: 309 });
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
  it('a deny that lands while the rows are being read still stops the download (security review #6)', async () => {
    const id = ((await call(h, 'export.request', { ...as(RYAN), app: 'gather-app', accounts: [HOST] })).body.request as { id: string }).id;
    await call(h, 'export.approve', { ...as(PAUL), id });
    h.whileReading(async () => { await call(h, 'export.deny', { ...as(PAUL), id }); });
    const got = await call(h, 'export.fetch', { ...as(RYAN), id });
    expect(got.status).toBe(403);
    expect(JSON.stringify(got.body)).not.toContain('pastor@grace.org');
  });
  it('the request list never carries the accounts', async () => {
    await call(h, 'export.request', { ...as(RYAN), app: 'gather-app', accounts: [HOST] });
    const list = await call(h, 'export.list', as(PAUL));
    expect(JSON.stringify(list.body)).not.toContain(HOST);
  });
});

describe('sealed at the data layer (2026-10-27)', () => {
  const vaultText = () => JSON.stringify([...h.vault.entries()]);
  it('after recording, importing and exporting, no email is in the clear anywhere in the vault', async () => {
    await call(h, 'directory.record', { session: `session:${HOST}:pastor@grace.org`, email: 'pastor@grace.org' });
    await call(h, 'directory.import', { ...as(RYAN), records: [{ account: CHURCH, email: 'office@grace.org', verifiedAt: 1 }] });
    const id = ((await call(h, 'export.request', { ...as(RYAN), app: 'gcid', accounts: [HOST, CHURCH] })).body.request as { id: string }).id;
    await call(h, 'export.approve', { ...as(PAUL), id });
    const got = await call(h, 'export.fetch', { ...as(RYAN), id });
    // The approved download still carries the real addresses...
    expect((got.body.rows as { email: string }[]).map((r) => r.email)).toEqual(['pastor@grace.org', 'office@grace.org']);
    // ...but a steward reading the vault directly sees neither.
    expect(vaultText()).not.toContain('pastor@grace.org');
    expect(vaultText()).not.toContain('office@grace.org');
  });
  it('a record written before sealing still reads, and the seal step rewrites it sealed', async () => {
    h.vault.set(`contact:${HOST}`, { v: 2, email: 'pastor@grace.org', verifiedAt: 5, source: `org-default:${RYAN}` });
    expect((await call(h, 'directory.reveal', { ...as(RYAN), account: HOST })).body).toMatchObject({ email: 'pastor@grace.org' });
    expect((await call(h, 'directory.masked', { ...as(RYAN), accounts: [HOST] })).body.contacts).toMatchObject({ [HOST]: { masked: 'pa•••r@g•••.org', source: 'org-default' } });
    // No accounts are passed: it walks the directory's own records, so a record for an account the Home no longer
    // lists is sealed too.
    const r = await call(h, 'directory.seal', { ...as(RYAN) });
    expect(r.body).toMatchObject({ sealed: 1, checked: 1, total: 1 });
    expect(r.body.next).toBeUndefined();
    expect(h.vault.get(`contact:${HOST}`)).toMatchObject({ v: 3, source: 'org-default', verifiedAt: 5 });
    expect(vaultText()).not.toContain('pastor@grace.org');
    expect(vaultText()).not.toContain('org-default:'); // the old source's address went with it
    expect((await call(h, 'directory.reveal', { ...as(RYAN), account: HOST })).body).toMatchObject({ email: 'pastor@grace.org' });
    expect(audit(h).some((e) => e.kind === 'seal')).toBe(true);
  });
  it('sealing is admin-only', async () => {
    expect((await call(h, 'directory.seal', { ...as(MALLORY), accounts: [HOST] })).status).toBe(403);
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
