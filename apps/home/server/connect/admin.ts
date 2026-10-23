// GET /connect/admin/{me,accounts,org-types,organizations,azure-costs}  (Bearer session) — the Admin tab (Global.Church, 2026-10-09).
//
// The SERVER decides who is an admin, on every call: the session's person address must be on `HOME_ADMINS`. The
// menu only hides the row; these routes refuse a non-admin with 403 whatever the page does. An empty list is
// nobody (no fallback admin).
//
// Numbers only: no emails, no names, no addresses leave these routes — counts and dollars. The exceptions:
// /org-types (2026-10-21): the words people typed for an "Other" organization type, so the team can find what the
// ontology is missing. Those words, with a date, and nothing that says whose they are. And /organizations (2026-10-22),
// which lists organizations with their managers' emails, and records every view.
import { importJwks, verifyAgentSession } from '@agenticprimitives/connect';
import { getServer, ownIssuer, type Env, type FnContext, type KVNamespace } from '../_lib/server-broker';
import {
  FACET_PREFIXES, countAccounts, countOrgs, dayOf, growth, isAdmin, listAppOrganizations, parseAdmins, recordSnapshot, tallyOrgTypes,
  type AccountCounts, type AppOrg, type OrgCounts, type OrgTypeTally, type Snapshot,
} from '../../src/lib/admin-stats';
import { costQueries, parseLabels, shapeCosts, type CostTable, type CostsResult } from '../../src/lib/azure-costs';
import { TEST_AGENT_PREFIX, testAddresses } from '../../src/lib/test-identity';
import { accountAddress, contactDirectoryEnabled, contactViews, readContactEmails, recordContactView, type ContactView } from '../_lib/contact-directory';
import { directoryOp, operatorAdmin, operatorOrg } from '../_lib/operator-directory';
import type { IncomingDelegation } from '../_lib/verify-delegation';

const json = (b: unknown, s = 200): Response =>
  new Response(JSON.stringify(b), { status: s, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });

type Gate = { ok: true; admin: boolean; sub: string; token: string; stewardship: IncomingDelegation | null } | { ok: false; res: Response };

async function session(request: Request, env: Env): Promise<Gate> {
  const auth = request.headers.get('authorization') ?? '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  if (!token) return { ok: false, res: json({ error: 'session required' }, 401) };
  const { jwks } = await getServer(env);
  const keys = await importJwks(jwks);
  const v = await verifyAgentSession(token, { keys, expectedAud: env.DEMO_SSO_AUD ?? 'demo-sso', expectedIss: ownIssuer(request, env) });
  if (!v.ok) return { ok: false, res: json({ error: 'invalid session' }, 401) };
  // With an operator org configured (2026-10-23), an admin is a STEWARD of it, verified on-chain (operator-directory.ts);
  // HOME_ADMINS no longer counts. Without one, the list as before. A switch, not a fallback.
  if (operatorOrg(env)) {
    const stewardship = await operatorAdmin(env, accountAddress(String(v.session.sub)) ?? '');
    return { ok: true, admin: !!stewardship, sub: String(v.session.sub), token, stewardship };
  }
  return { ok: true, admin: isAdmin(v.session.sub, parseAdmins(env.HOME_ADMINS)), sub: String(v.session.sub), token, stewardship: null };
}

/** 401 without a valid session, 403 for anyone not on HOME_ADMINS; null = go ahead. */
export async function requireAdmin(request: Request, env: Env): Promise<Response | null> {
  const g = await session(request, env);
  if (!g.ok) return g.res;
  return g.admin ? null : json({ error: 'not an admin of this Home' }, 403);
}

/** Whether to show the Admin row. A bad session is simply "no". */
export const onAdminMe = async ({ request, env }: FnContext): Promise<Response> => {
  const g = await session(request, env);
  // The operator org's address (2026-10-23), so an admin's page can sign the one-time directory grant as it.
  return json({ admin: g.ok && g.admin, ...(g.ok && g.admin && operatorOrg(env) ? { operatorOrg: operatorOrg(env) } : {}) });
};

// ── Accounts ─────────────────────────────────────────────────────────────────────────────────────────────────────

const ACCOUNTS_CACHE = 'admin-cache:accounts';
const SNAPSHOTS = 'admin-snap:accounts';
const ACCOUNTS_TTL_S = 10 * 60;

async function listKeys(kv: KVNamespace, prefix: string): Promise<string[]> {
  const out: string[] = [];
  let cursor: string | undefined;
  for (let i = 0; i < 2000; i++) {
    const page = await kv.list({ prefix, ...(cursor ? { cursor } : {}), limit: 1000 });
    out.push(...page.keys.map((k) => k.name));
    if (page.list_complete || !page.cursor) break;
    cursor = page.cursor;
  }
  return [...new Set(out)];
}

async function readAll(kv: KVNamespace, keys: string[]): Promise<{ key: string; value: string | null }[]> {
  const out: { key: string; value: string | null }[] = [];
  for (let i = 0; i < keys.length; i += 50) {
    const batch = keys.slice(i, i + 50);
    out.push(...(await Promise.all(batch.map(async (key) => ({ key, value: await kv.get(key) })))));
  }
  return out;
}

export interface AccountsView extends AccountCounts, OrgCounts {
  new7d: number | null;
  new30d: number | null;
  trackingSince: string | null;
  /** New since the first daily count: what the tiles show until a full 7 / 30 days of counts exist. */
  newSinceTracking: number;
  history: Snapshot[];
  asOf: number;
}

export async function computeAccounts(kv: KVNamespace, now: number): Promise<AccountsView> {
  const facetKeys = (await Promise.all(FACET_PREFIXES.map((p) => listKeys(kv, p)))).flat();
  // Test identities (src/lib/test-identity.ts), marked at sign-in: left out of every count, said separately.
  const testPeople = testAddresses(await listKeys(kv, TEST_AGENT_PREFIX));
  const accounts = countAccounts(await readAll(kv, facetKeys), testPeople);
  const orgs = countOrgs(await readAll(kv, await listKeys(kv, 'related:')), now, testPeople);
  let history: Snapshot[] = [];
  try {
    history = JSON.parse((await kv.get(SNAPSHOTS)) ?? '[]') as Snapshot[];
  } catch {
    history = [];
  }
  history = recordSnapshot(history, { date: dayOf(now), accounts: accounts.accounts, organizations: orgs.organizations });
  await kv.put(SNAPSHOTS, JSON.stringify(history));
  return {
    ...accounts,
    ...orgs,
    new7d: growth(history, now, 7, 'accounts'),
    new30d: growth(history, now, 30, 'accounts'),
    trackingSince: history[0]?.date ?? null,
    newSinceTracking: accounts.accounts - (history[0]?.accounts ?? accounts.accounts),
    history: history.slice(-90),
    asOf: now,
  };
}

export const onAdminAccounts = async ({ request, env }: FnContext): Promise<Response> => {
  const refused = await requireAdmin(request, env);
  if (refused) return refused;
  const refresh = new URL(request.url).searchParams.get('refresh') === '1';
  if (!refresh) {
    const cached = await env.AUTH_CODES.get(ACCOUNTS_CACHE);
    if (cached) return new Response(cached, { headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });
  }
  const view = await computeAccounts(env.AUTH_CODES, Date.now());
  const body = JSON.stringify(view);
  await env.AUTH_CODES.put(ACCOUNTS_CACHE, body, { expirationTtl: ACCOUNTS_TTL_S });
  return new Response(body, { headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });
};

// ── Organization types (2026-10-21) ─────────────────────────────────────────────────────────────────────────────

export interface OrgTypesView extends OrgTypeTally {
  asOf: number;
}

/** GET /connect/admin/org-types — computed on each call (no cache key): one pass over the related links. */
export const onAdminOrgTypes = async ({ request, env }: FnContext): Promise<Response> => {
  const refused = await requireAdmin(request, env);
  if (refused) return refused;
  const kv = env.AUTH_CODES;
  const testPeople = testAddresses(await listKeys(kv, TEST_AGENT_PREFIX));
  const tally = tallyOrgTypes(await readAll(kv, await listKeys(kv, 'related:')), testPeople);
  return json({ ...tally, asOf: Date.now() } satisfies OrgTypesView);
};

// ── Organizations by app (2026-10-22) ────────────────────────────────────────────────────────────────────────────
// GET /connect/admin/organizations?app=<client id>. Every organization an app brought to this Home, with its name,
// type, created date, and the contact email of each person who manages it (contact-directory.ts). It replaces the
// one-at-a-time Contact lookup (2026-10-21): Paul wants the list. This is the one Admin route that returns email
// addresses; each call is recorded once (who, when, which app, how many addresses), and the page shows that record.

/** The apps the tab can show, by OIDC client id. Gather is the only one today. */
export const ADMIN_APPS = [{ id: 'gather-app', label: 'Gather' }] as const;

export interface OrgContact { account: string; email: string | null; verifiedAt: number | null }
export interface OrganizationRow extends Omit<AppOrg, 'stewards'> {
  /** The organization's own contact email (org-contact.ts): its creator's to begin with, changed only by a code. */
  orgContact: { email: string; verifiedAt: number; changed: boolean } | null;
  /** The people who manage it, at the email they sign in with. */
  contacts: OrgContact[];
}
export interface OrganizationsView {
  apps: { id: string; label: string }[];
  app: string;
  /** False when this Home has no CONTACT_DIRECTORY_KEY: organizations are listed, emails are not. */
  emails: boolean;
  /** True with the operator directory (2026-10-23): every address here is MASKED; a full one comes from a reveal or an
   *  approved export (POST /connect/admin/directory). */
  masked?: boolean;
  orgs: OrganizationRow[];
  /** The last views of this list, newest first (this one included). */
  views: ContactView[];
  asOf: number;
}

export const onAdminOrganizations = async ({ request, env }: FnContext): Promise<Response> => {
  const g = await session(request, env);
  if (!g.ok) return g.res;
  if (!g.admin) return json({ error: 'not an admin of this Home' }, 403);
  const app = new URL(request.url).searchParams.get('app') ?? ADMIN_APPS[0].id;
  if (!ADMIN_APPS.some((a) => a.id === app)) return json({ error: `unknown app: ${app}` }, 400);
  const kv = env.AUTH_CODES;
  const testPeople = testAddresses(await listKeys(kv, TEST_AGENT_PREFIX));
  const orgs = listAppOrganizations(await readAll(kv, await listKeys(kv, 'related:')), app, testPeople);
  if (operatorOrg(env)) {
    const accounts = [...new Set(orgs.flatMap((o) => [o.org, ...o.stewards]))];
    const r = await directoryOp(env, 'directory.masked', { session: g.token, stewardship: g.stewardship, accounts });
    if (r.status !== 200) return json({ error: String(r.body.error ?? 'the directory is unavailable') }, r.status === 409 ? 409 : 502);
    const c = (r.body.contacts ?? {}) as Record<string, { masked: string; verifiedAt: number; source: string }>;
    const rowsM: OrganizationRow[] = orgs.map(({ stewards, ...o }) => ({
      ...o,
      orgContact: c[o.org] ? { email: c[o.org]!.masked, verifiedAt: c[o.org]!.verifiedAt, changed: c[o.org]!.source === 'org-verified' } : null,
      contacts: stewards.map((account) => ({ account, email: c[account]?.masked ?? null, verifiedAt: c[account]?.verifiedAt ?? null })),
    }));
    return json({ apps: [...ADMIN_APPS], app, emails: true, masked: true, orgs: rowsM, views: [], asOf: Date.now() } satisfies OrganizationsView);
  }
  const emails = contactDirectoryEnabled(env);
  const found = emails ? await readContactEmails(env, orgs.flatMap((o) => [o.org, ...o.stewards])) : new Map();
  const rows: OrganizationRow[] = orgs.map(({ stewards, ...o }) => ({
    ...o,
    orgContact: found.get(o.org) ? { email: found.get(o.org)!.email, verifiedAt: found.get(o.org)!.verifiedAt, changed: found.get(o.org)!.source.startsWith('org-verified') } : null,
    contacts: stewards.map((account) => ({ account, email: found.get(account)?.email ?? null, verifiedAt: found.get(account)?.verifiedAt ?? null })),
  }));
  const now = Date.now();
  if (emails) await recordContactView(kv, { by: accountAddress(g.sub) ?? g.sub, at: now, what: `organizations: ${app}`, count: found.size });
  return json({ apps: [...ADMIN_APPS], app, emails, orgs: rows, views: await contactViews(kv, 10), asOf: now } satisfies OrganizationsView);
};

// ── The operator directory's admin actions (2026-10-23) ──────────────────────────────────────────────────────────
// POST /connect/admin/directory {action, ...}: reveal one address, the audit log, and the two-admin export (request,
// list, approve, deny, fetch). Each carries the admin's own session and stewardship to the operator org's DO, which
// decides and records. `import` moves the old encrypted KV directory in, once.
const DIRECTORY_ACTIONS: Record<string, string> = {
  reveal: 'directory.reveal', audit: 'directory.audit', 'export-request': 'export.request', 'export-list': 'export.list',
  'export-approve': 'export.approve', 'export-deny': 'export.deny', 'export-fetch': 'export.fetch', import: 'directory.import', enable: 'directory.enable',
};

export const onAdminDirectory = async ({ request, env }: FnContext): Promise<Response> => {
  if (!operatorOrg(env)) return json({ error: 'the operator directory is not configured' }, 503);
  const body = (await request.json().catch(() => ({}))) as Record<string, unknown>;
  const op = DIRECTORY_ACTIONS[String(body.action ?? '')];
  if (!op) return json({ error: 'unknown action' }, 400);
  const g = await session(request, env);
  if (!g.ok) return g.res;
  // `enable` is the one action before anyone is an admin by the directory's own rules: the DO checks stewardship itself.
  const stewardship = g.stewardship ?? (op === 'directory.enable' ? body.stewardship : null);
  if (!g.admin && op !== 'directory.enable') return json({ error: 'not an admin of this Home' }, 403);
  const { action: _a, session: _s, stewardship: _w, ...rest } = body;
  if (op === 'directory.import') {
    // The old KV copies, decrypted once here with the old key and handed to the DO, which records the import.
    const keys = (await listKeys(env.AUTH_CODES, 'contact:0x')).map((k) => k.slice('contact:'.length));
    const found = await readContactEmails(env, keys);
    const records = [...found].map(([account, c]) => ({ account, email: c.email, verifiedAt: c.verifiedAt, source: c.source }));
    const r = await directoryOp(env, op, { session: g.token, stewardship, records });
    return json({ ...r.body, found: records.length }, r.status);
  }
  const r = await directoryOp(env, op, { ...rest, session: g.token, stewardship });
  return json(r.body, r.status);
};

// ── Azure ────────────────────────────────────────────────────────────────────────────────────────────────────────

const AZURE_CACHE = 'admin-cache:azure';
const AZURE_TTL_S = 6 * 60 * 60;
/** A refresh within this long of the last real fetch serves the cache: Cost Management throttles hard. */
const AZURE_MIN_REFRESH_MS = 10 * 60 * 1000;
const ARM = 'https://management.azure.com';

async function azureToken(env: Env): Promise<string> {
  const res = await fetch(`https://login.microsoftonline.com/${encodeURIComponent(env.AZURE_TENANT_ID!)}/oauth2/v2.0/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'client_credentials',
      client_id: env.AZURE_CLIENT_ID!,
      client_secret: env.AZURE_CLIENT_SECRET!,
      scope: `${ARM}/.default`,
    }),
  });
  const j = (await res.json().catch(() => ({}))) as { access_token?: string; error?: string };
  if (!res.ok || !j.access_token) throw new Error(`Azure sign-in failed (${j.error ?? res.status})`);
  return j.access_token;
}

async function arm<T>(token: string, method: 'GET' | 'POST', path: string, body?: unknown): Promise<T> {
  const res = await fetch(`${ARM}${path}`, {
    method,
    headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  if (!res.ok) {
    const j = (await res.json().catch(() => ({}))) as { error?: { code?: string } };
    throw new Error(`Azure ${res.status}${j.error?.code ? ` ${j.error.code}` : ''}`);
  }
  return (await res.json()) as T;
}

export async function fetchCosts(env: Env, now: Date): Promise<CostsResult> {
  if (!env.AZURE_TENANT_ID || !env.AZURE_CLIENT_ID || !env.AZURE_CLIENT_SECRET || !env.AZURE_SUBSCRIPTION_ID) {
    return { ok: false, reason: 'Azure cost reading is not set up on this Home.', asOf: now.getTime() };
  }
  try {
    const token = await azureToken(env);
    const scope = `/subscriptions/${encodeURIComponent(env.AZURE_SUBSCRIPTION_ID)}`;
    const q = costQueries(now);
    const query = (b: unknown) => arm<CostTable>(token, 'POST', `${scope}/providers/Microsoft.CostManagement/query?api-version=2023-11-01`, b);
    // Sequential, not parallel: Cost Management throttles concurrent queries per scope.
    const monthByGroup = await query(q.monthByGroup);
    const soft = async <T>(p: () => Promise<T>): Promise<T | null> => { try { return await p(); } catch { return null; } };
    const lastMonth = await soft(() => query(q.lastMonth));
    const daily = await soft(() => query(q.daily));
    const forecast = q.forecast
      ? await soft(() => arm<CostTable>(token, 'POST', `${scope}/providers/Microsoft.CostManagement/forecast?api-version=2023-11-01`, q.forecast))
      : null;
    const budgets = await soft(() => arm<{ value?: [] }>(token, 'GET', `${scope}/providers/Microsoft.Consumption/budgets?api-version=2023-05-01`));
    return shapeCosts({
      monthByGroup, lastMonth, daily, forecast, budgets,
      ...(env.AZURE_BUDGET_NAME ? { budgetName: env.AZURE_BUDGET_NAME } : {}),
      labels: parseLabels(env.AZURE_RG_LABELS),
      monthStart: q.monthStart,
      noDaysLeft: !q.forecast,
      now: now.getTime(),
    });
  } catch (e) {
    return { ok: false, reason: `Azure did not answer: ${(e as Error).message}`, asOf: now.getTime() };
  }
}

export const onAdminAzureCosts = async ({ request, env }: FnContext): Promise<Response> => {
  const refused = await requireAdmin(request, env);
  if (refused) return refused;
  const refresh = new URL(request.url).searchParams.get('refresh') === '1';
  const cachedRaw = await env.AUTH_CODES.get(AZURE_CACHE);
  const cached = cachedRaw ? (JSON.parse(cachedRaw) as CostsResult) : null;
  if (cached && (!refresh || Date.now() - cached.asOf < AZURE_MIN_REFRESH_MS)) return json(cached);
  const fresh = await fetchCosts(env, new Date());
  // A failure is cached briefly only, so a fixed configuration shows up within minutes.
  await env.AUTH_CODES.put(AZURE_CACHE, JSON.stringify(fresh), { expirationTtl: fresh.ok ? AZURE_TTL_S : 5 * 60 });
  return json(fresh);
};
