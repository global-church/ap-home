// The operator directory's operations, run by the OPERATOR ORG's InteractionsDO (design: gc-estate/docs/
// operator-workspace.md; policy: operator-directory.ts). Everything the DO provides arrives through `DirectoryCtx`,
// so every admission and refusal here is tested without a Durable Object (test/operator-directory-ops.test.ts).
//
// Admission, per op (none is a bearer credential):
//   directory.record                 the person's own session, which must PROVE the email (sign-in hash)
//   directory.defaultOrg / recordOrg  a session + that ORG's stewardship grant (on-chain, unrevoked)
//   everything else                  a session + THIS operator org's stewardship grant (an admin)
import {
  appendAudit, AUDIT_LOG, canApprove, canDeny, canFetch, cleanEmail, contactKey, DIRECTORY_SCOPE, EXPORTS_DOC,
  exportSummary, isAccount, keepExports, maskEmail, newExportRequest, readContact, sessionProvesEmail, sourceKind,
  type AuditEntry, type ContactRecord, type ExportRequest, type SealedContact,
} from './operator-directory.js';

export interface Wire { delegator: string; delegate: string; signature?: string; caveats: { enforcer: string; terms: string; args?: string }[]; salt: string | number | bigint; authority?: string }

export interface DirectoryCtx {
  /** The operator org (this DO's principal), lower-case. */
  principal: string;
  now(): number;
  newId(): string;
  verifySession(session: string): Promise<{ ok: true; sa: string; principal?: { kind: string; id: string } } | { ok: false; error: string }>;
  /** Stewardship of `org` held by `sa`: shape + ERC-1271 + window + not revoked. */
  isSteward(org: string, sa: string, wire: Wire | undefined): Promise<boolean>;
  /** The grant verifies (ERC-1271) against its delegator. */
  grantSignatureOk(wire: Wire): Promise<boolean>;
  /** The record scope a grant carries: [{resources, ops}], or null when it carries none / is undecodable. */
  recordScopes(wire: Wire): { resources: string[]; ops: string[] }[] | null;
  /** The delegate the directory grant must name: the account this org's session leaf lets the DO act through (the
   *  delegate of its interactions grant). '' when the org has none yet, which refuses enabling. */
  expectedDelegate(): Promise<string>;
  getGrant(): Promise<Wire | undefined>;
  setGrant(wire: Wire): Promise<void>;
  read(grant: Wire, resource: string): Promise<unknown>;
  readMany(grant: Wire, resources: string[]): Promise<Record<string, unknown>>;
  write(grant: Wire, resource: string, data: unknown): Promise<void>;
  /** Run read-modify-write work on a shared record one at a time. */
  serial<T>(key: string, work: () => Promise<T>): Promise<T>;
  /** Encrypt / decrypt one account's email under the directory's data key (directory-seal.ts). A record is only ever
   *  written sealed; there is no unsealed fallback. */
  seal(account: string, email: string): Promise<string>;
  open(account: string, sealed: string): Promise<string>;
}

type Out = { status: number; body: Record<string, unknown> };
const ok = (body: Record<string, unknown> = {}): Out => ({ status: 200, body: { ok: true, ...body } });
const no = (status: number, error: string): Out => ({ status, body: { ok: false, error } });

export const DIRECTORY_OPS = new Set([
  'directory.enable', 'directory.record', 'directory.defaultOrg', 'directory.recordOrg', 'directory.masked',
  'directory.reveal', 'directory.audit', 'directory.import', 'directory.oldRemoved', 'directory.seal', 'export.request', 'export.list', 'export.approve',
  'export.deny', 'export.fetch',
]);

/** The directory grant's scope must be exactly the directory's records, read+write, nothing else. */
export function directoryScopeExact(scopes: { resources: string[]; ops: string[] }[] | null): boolean {
  if (!scopes || !scopes.length) return false;
  const resources = new Set(scopes.flatMap((s) => s.resources));
  if (resources.size !== DIRECTORY_SCOPE.length || !DIRECTORY_SCOPE.every((r) => resources.has(r))) return false;
  return DIRECTORY_SCOPE.every((r) => {
    const ops = new Set(scopes.filter((s) => s.resources.includes(r)).flatMap((s) => s.ops));
    return ops.has('read') && ops.has('write');
  });
}

async function chunkedRead(ctx: DirectoryCtx, grant: Wire, accounts: string[]): Promise<Map<string, ContactRecord>> {
  const out = new Map<string, ContactRecord>();
  for (let i = 0; i < accounts.length; i += 50) {
    const slice = accounts.slice(i, i + 50);
    const got = await ctx.readMany(grant, slice.map(contactKey));
    for (const a of slice) {
      const c = readContact(got[contactKey(a)]);
      if (c) out.set(a, c);
    }
  }
  return out;
}

/** The record a contact is written as: sealed, with its masked form beside it. */
async function sealedContact(ctx: DirectoryCtx, account: string, email: string, verifiedAt: number, source: string): Promise<SealedContact> {
  return { v: 3, sealed: await ctx.seal(account, email), masked: maskEmail(email), verifiedAt, source };
}
/** The email a record holds: opened when sealed, as written when it predates sealing. */
const emailOf = (ctx: DirectoryCtx, account: string, c: ContactRecord): Promise<string> =>
  c.v === 2 ? Promise.resolve(c.email) : ctx.open(account, c.sealed);
const maskedOf = (c: ContactRecord): string => (c.v === 2 ? maskEmail(c.email) : c.masked);

async function audit(ctx: DirectoryCtx, grant: Wire, entry: Omit<AuditEntry, 'at'>): Promise<void> {
  await ctx.serial(AUDIT_LOG, async () => {
    const log = (await ctx.read(grant, AUDIT_LOG)) as AuditEntry[] | null;
    await ctx.write(grant, AUDIT_LOG, appendAudit(log, { ...entry, at: ctx.now() }));
  });
}

export async function handleDirectoryOp(ctx: DirectoryCtx, op: string, body: Record<string, unknown>): Promise<Out> {
  const session = String(body.session ?? '');
  const who = await ctx.verifySession(session);
  if (!who.ok) return no(401, who.error);
  const sa = who.sa.toLowerCase();

  // ── Writes that come from the person or org the record is about ──
  if (op === 'directory.record') {
    const email = cleanEmail(body.email);
    if (!email) return no(400, 'a valid email is required');
    if (!(await sessionProvesEmail(who.principal, email))) return no(403, 'this session did not sign in with that email');
    const grant = await ctx.getGrant();
    if (!grant) return no(409, 'the operator directory is not enabled');
    await ctx.write(grant, contactKey(sa), await sealedContact(ctx, sa, email, ctx.now(), 'email-sign-in'));
    return ok();
  }
  if (op === 'directory.defaultOrg' || op === 'directory.recordOrg') {
    const org = String(body.org ?? '').toLowerCase();
    if (!isAccount(org)) return no(400, 'org must be an organization address');
    // Security review 2026-10-23 (#5): a self-signed "stewardship" of your own account would otherwise let you write
    // your own record with an address you never verified.
    if (org === sa) return no(400, 'an account is not its own organization');
    if (!(await ctx.isSteward(org, sa, body.stewardship as Wire | undefined))) return no(403, 'only someone who manages this organization can set its contact');
    const grant = await ctx.getGrant();
    if (!grant) return no(409, 'the operator directory is not enabled');
    if (op === 'directory.recordOrg') {
      const email = cleanEmail(body.email);
      if (!email) return no(400, 'a valid email is required');
      // The session must prove the address (#5): GCID mints one only after the code sent to it was entered, so a
      // steward calling here directly cannot skip the code.
      if (!(await sessionProvesEmail(who.principal, email))) return no(403, 'this address has not been verified with a code');
      await ctx.write(grant, contactKey(org), await sealedContact(ctx, org, email, ctx.now(), 'org-verified'));
      // Who set it is recorded here, not on the record (Paul, 2026-10-27: the record carries no address).
      await audit(ctx, grant, { by: sa, kind: 'org-contact', account: org, note: 'verified' });
      return ok();
    }
    // The creator's own verified address, copied; never supplied by the caller, never over an existing contact.
    const [existing, mine] = await Promise.all([ctx.read(grant, contactKey(org)), ctx.read(grant, contactKey(sa))]);
    if (readContact(existing)) return ok({ recorded: false, reason: 'the organization already has a contact' });
    const me = readContact(mine);
    if (!me) return ok({ recorded: false, reason: 'no verified email on file for you yet' });
    await ctx.write(grant, contactKey(org), await sealedContact(ctx, org, await emailOf(ctx, sa, me), ctx.now(), 'org-default'));
    await audit(ctx, grant, { by: sa, kind: 'org-contact', account: org, note: 'default' });
    return ok({ recorded: true });
  }

  // ── Everything else: an admin of THIS operator org ──
  if (!(await ctx.isSteward(ctx.principal, sa, body.stewardship as Wire | undefined))) {
    return no(403, 'only an admin (someone the operator organization granted stewardship) may do this');
  }

  if (op === 'directory.enable') {
    const wire = body.delegation as Wire | undefined;
    if (!wire?.signature || wire.delegator.toLowerCase() !== ctx.principal) return no(400, 'a grant from the operator organization is required');
    const expected = (await ctx.expectedDelegate()).toLowerCase();
    if (!expected) return no(409, 'enable this organization’s storage first (it has no interactions grant)');
    if (wire.delegate.toLowerCase() !== expected) return no(403, 'the grant must name the directory service');
    if (!directoryScopeExact(ctx.recordScopes(wire))) return no(403, 'the grant must cover exactly the directory records, read and write');
    if (!(await ctx.grantSignatureOk(wire))) return no(403, 'the grant does not verify against the operator organization');
    await ctx.setGrant(wire);
    await audit(ctx, wire, { by: sa, kind: 'enable' });
    return ok();
  }

  const grant = await ctx.getGrant();
  if (!grant) return no(409, 'the operator directory is not enabled');

  if (op === 'directory.masked') {
    const accounts = Array.isArray(body.accounts) ? [...new Set(body.accounts.filter(isAccount).map((a) => a.toLowerCase()))].slice(0, 5000) : [];
    const found = await chunkedRead(ctx, grant, accounts);
    await audit(ctx, grant, { by: sa, kind: 'list', accounts: found.size });
    const contacts: Record<string, { masked: string; verifiedAt: number; source: string }> = {};
    for (const [a, c] of found) contacts[a] = { masked: maskedOf(c), verifiedAt: c.verifiedAt, source: sourceKind(c.source) };
    return ok({ contacts });
  }
  if (op === 'directory.reveal') {
    const account = String(body.account ?? '').toLowerCase();
    if (!isAccount(account)) return no(400, 'account required');
    const c = readContact(await ctx.read(grant, contactKey(account)));
    // Recorded BEFORE the address is returned: a reveal that is not in the log does not happen.
    await audit(ctx, grant, { by: sa, kind: 'reveal', account });
    return ok({ email: c ? await emailOf(ctx, account, c) : null, verifiedAt: c?.verifiedAt ?? null });
  }
  if (op === 'directory.audit') {
    const log = ((await ctx.read(grant, AUDIT_LOG)) as AuditEntry[] | null) ?? [];
    return ok({ entries: [...log].reverse().slice(0, Math.min(Number(body.limit ?? 50) || 50, 500)) });
  }
  if (op === 'directory.oldRemoved') {
    // The Home is about to delete the old encrypted KV directory (2026-10-26). Recorded here, BEFORE it happens, with
    // who and how many: the old store has no log of its own.
    const count = Math.max(0, Math.floor(Number(body.count ?? 0)) || 0);
    await audit(ctx, grant, { by: sa, kind: 'old-removed', accounts: count });
    return ok();
  }
  if (op === 'directory.import') {
    const rows = Array.isArray(body.records) ? (body.records as { account?: unknown; email?: unknown; verifiedAt?: unknown; source?: unknown }[]) : [];
    let n = 0;
    // One batch per call (the caller sends them one at a time): a single read says which accounts already have a
    // record — a live record is newer than the old copy and is kept — so a batch costs one read plus its writes.
    const batch = rows.slice(0, 50);
    const have = await chunkedRead(ctx, grant, batch.map((r) => String(r.account ?? '').toLowerCase()).filter(isAccount));
    for (const r of batch) {
      const account = String(r.account ?? '').toLowerCase();
      const email = cleanEmail(r.email);
      if (!isAccount(account) || !email || have.has(account)) continue;
      const at = typeof r.verifiedAt === 'number' ? r.verifiedAt : ctx.now();
      await ctx.write(grant, contactKey(account), await sealedContact(ctx, account, email, at, 'import'));
      n++;
    }
    await audit(ctx, grant, { by: sa, kind: 'import', accounts: n });
    return ok({ imported: n });
  }
  if (op === 'directory.seal') {
    // One-time migration (2026-10-27): rewrite the records written before sealing, a batch of at most 50 per call, so
    // no email is left in the clear in the vault. The vault keeps no history of a record, so the clear copy is gone.
    const accounts = Array.isArray(body.accounts) ? [...new Set(body.accounts.filter(isAccount).map((a) => a.toLowerCase()))].slice(0, 50) : [];
    const found = await chunkedRead(ctx, grant, accounts);
    let n = 0;
    for (const [a, c] of found) {
      if (c.v !== 2) continue;
      await ctx.write(grant, contactKey(a), await sealedContact(ctx, a, c.email, c.verifiedAt, sourceKind(c.source)));
      n++;
    }
    await audit(ctx, grant, { by: sa, kind: 'seal', accounts: n });
    return ok({ sealed: n, checked: found.size });
  }

  // ── Exports ──
  if (op === 'export.list') {
    const list = keepExports((await ctx.read(grant, EXPORTS_DOC)) as ExportRequest[] | null);
    const now = ctx.now();
    return ok({ requests: [...list].reverse().map((r) => exportSummary(r, now)) });
  }
  if (op === 'export.request') {
    const req = newExportRequest({ id: ctx.newId(), app: String(body.app ?? ''), accounts: body.accounts, requestedBy: sa, now: ctx.now(), note: body.note });
    if ('error' in req) return no(400, req.error);
    await ctx.serial(EXPORTS_DOC, async () => {
      const list = keepExports((await ctx.read(grant, EXPORTS_DOC)) as ExportRequest[] | null);
      await ctx.write(grant, EXPORTS_DOC, keepExports([...list, req]));
    });
    await audit(ctx, grant, { by: sa, kind: 'export-request', exportId: req.id, accounts: req.accounts.length });
    return ok({ request: exportSummary(req, ctx.now()) });
  }
  if (op === 'export.approve' || op === 'export.deny' || op === 'export.fetch') {
    const id = String(body.id ?? '');
    let refused: string | null = null;
    let target: ExportRequest | null = null;
    await ctx.serial(EXPORTS_DOC, async () => {
      const list = keepExports((await ctx.read(grant, EXPORTS_DOC)) as ExportRequest[] | null);
      const i = list.findIndex((r) => r.id === id);
      if (i < 0) { refused = 'no such export'; return; }
      const r = list[i]!;
      const now = ctx.now();
      const v = op === 'export.approve' ? canApprove(r, sa, now) : op === 'export.deny' ? canDeny(r, now) : canFetch(r, sa, now);
      if (!v.ok) { refused = v.reason; return; }
      if (op === 'export.fetch') { target = r; return; } // marked downloaded only after the data is read and the fetch recorded
      list[i] = op === 'export.approve' ? { ...r, approvedBy: sa, approvedAt: now } : { ...r, deniedBy: sa, deniedAt: now };
      target = list[i]!;
      await ctx.write(grant, EXPORTS_DOC, list);
    });
    if (refused) return no(403, refused);
    const r = target as unknown as ExportRequest;
    if (op !== 'export.fetch') {
      await audit(ctx, grant, { by: sa, kind: op === 'export.approve' ? 'export-approve' : 'export-deny', exportId: r.id, accounts: r.accounts.length });
      return ok({ request: exportSummary(r, ctx.now()) });
    }
    const found = await chunkedRead(ctx, grant, r.accounts);
    // Opened BEFORE the export is marked downloaded, so a key-service failure leaves it downloadable rather than spent.
    const emails = new Map<string, string>();
    for (const [a, c] of found) emails.set(a, await emailOf(ctx, a, c));
    // Mark it downloaded and record it BEFORE any address is returned; if either write fails, nothing leaves.
    let raced = false;
    await ctx.serial(EXPORTS_DOC, async () => {
      const list = keepExports((await ctx.read(grant, EXPORTS_DOC)) as ExportRequest[] | null);
      const i = list.findIndex((x) => x.id === r.id);
      // Re-checked here (#6): a deny or the window closing while the rows were read still stops the download.
      if (i < 0 || !canFetch(list[i]!, sa, ctx.now()).ok) { raced = true; return; }
      list[i] = { ...list[i]!, fetchedAt: ctx.now() };
      await ctx.write(grant, EXPORTS_DOC, list);
    });
    if (raced) return no(403, 'this export is no longer available to download');
    await audit(ctx, grant, { by: sa, kind: 'export-fetch', exportId: r.id, accounts: found.size });
    const rows = r.accounts.map((a) => ({ account: a, email: emails.get(a) ?? null, verifiedAt: found.get(a)?.verifiedAt ?? null }));
    return ok({ app: r.app, approvedBy: r.approvedBy, rows });
  }
  return no(404, `unknown op ${op}`);
}
