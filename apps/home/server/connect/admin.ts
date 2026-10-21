// GET /connect/admin/{me,accounts,azure-costs}  (Bearer session) — the Admin tab (Global.Church, 2026-10-09).
//
// The SERVER decides who is an admin, on every call: the session's person address must be on `HOME_ADMINS`. The
// menu only hides the row; these routes refuse a non-admin with 403 whatever the page does. An empty list is
// nobody (no fallback admin).
//
// Numbers only: no emails, no names, no addresses leave these routes — counts and dollars. The one exception is
// /org-types (2026-10-21): the words people typed for an "Other" organization type, so the team can find what the
// ontology is missing. Those words, with a date, and nothing that says whose they are.
import { importJwks, verifyAgentSession } from '@agenticprimitives/connect';
import { getServer, ownIssuer, type Env, type FnContext, type KVNamespace } from '../_lib/server-broker';
import {
  FACET_PREFIXES, countAccounts, countOrgs, dayOf, growth, isAdmin, parseAdmins, recordSnapshot, tallyOrgTypes,
  type AccountCounts, type OrgCounts, type OrgTypeTally, type Snapshot,
} from '../../src/lib/admin-stats';
import { costQueries, parseLabels, shapeCosts, type CostTable, type CostsResult } from '../../src/lib/azure-costs';
import { TEST_AGENT_PREFIX, testAddresses } from '../../src/lib/test-identity';
import { accountAddress, contactDirectoryEnabled, contactLookups, lookUpContactEmail } from '../_lib/contact-directory';
import { readEmailFacet } from '../../src/lib/kv-indexer';

const json = (b: unknown, s = 200): Response =>
  new Response(JSON.stringify(b), { status: s, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });

type Gate = { ok: true; admin: boolean; sub: string } | { ok: false; res: Response };

async function session(request: Request, env: Env): Promise<Gate> {
  const auth = request.headers.get('authorization') ?? '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  if (!token) return { ok: false, res: json({ error: 'session required' }, 401) };
  const { jwks } = await getServer(env);
  const keys = await importJwks(jwks);
  const v = await verifyAgentSession(token, { keys, expectedAud: env.DEMO_SSO_AUD ?? 'demo-sso', expectedIss: ownIssuer(request, env) });
  if (!v.ok) return { ok: false, res: json({ error: 'invalid session' }, 401) };
  return { ok: true, admin: isAdmin(v.session.sub, parseAdmins(env.HOME_ADMINS)), sub: String(v.session.sub) };
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
  return json({ admin: g.ok && g.admin });
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

// ── Contact lookup (2026-10-21) ──────────────────────────────────────────────────────────────────────────────────
// GET /connect/admin/contact?q=<account or organization address, or an email>. The operator's contact directory
// (contact-directory.ts): the one Admin route that returns an email address, to an admin, with every read recorded.
//  - an account address → that person's contact email;
//  - an organization address → the contact email of each person who stewards it (its related links);
//  - an email → the account(s) that sign in with it (by its hash), and their contact email.

export interface ContactRow { account: string; relation: 'account' | 'steward'; email: string | null; verifiedAt: number | null; lookedUpBefore: number }
export interface ContactView { query: string; enabled: boolean; rows: ContactRow[] }

export const onAdminContact = async ({ request, env }: FnContext): Promise<Response> => {
  const g = await session(request, env);
  if (!g.ok) return g.res;
  if (!g.admin) return json({ error: 'not an admin of this Home' }, 403);
  const by = accountAddress(g.sub) ?? g.sub;
  const q = (new URL(request.url).searchParams.get('q') ?? '').trim().toLowerCase();
  if (!q) return json({ error: 'q required: an account or organization address, or an email' }, 400);
  if (!contactDirectoryEnabled(env)) return json({ query: q, enabled: false, rows: [] } satisfies ContactView);

  const accounts: { account: string; relation: ContactRow['relation'] }[] = [];
  if (q.includes('@')) {
    const facet = await readEmailFacet(env.AUTH_CODES, q);
    const a = facet ? accountAddress(String(facet)) : null;
    if (a) accounts.push({ account: a, relation: 'account' });
  } else if (/^0x[0-9a-f]{40}$/.test(q)) {
    accounts.push({ account: q, relation: 'account' });
    // As an organization: the people whose related link points at it.
    const stewards = (await listKeys(env.AUTH_CODES, 'related:')).filter((k) => k.split(':')[2]?.toLowerCase() === q);
    for (const k of stewards) {
      const person = k.split(':')[1]?.toLowerCase() ?? '';
      if (/^0x[0-9a-f]{40}$/.test(person) && person !== q && !accounts.some((x) => x.account === person)) accounts.push({ account: person, relation: 'steward' });
    }
  } else {
    return json({ error: 'not an address or an email' }, 400);
  }

  const rows: ContactRow[] = [];
  for (const { account, relation } of accounts) {
    const before = (await contactLookups(env.AUTH_CODES, account)).length;
    const found = await lookUpContactEmail(env, account, by);
    if (!found && relation === 'account' && accounts.length > 1) continue; // the org itself has no contact email
    rows.push({ account, relation, email: found?.email ?? null, verifiedAt: found?.verifiedAt ?? null, lookedUpBefore: before });
  }
  return json({ query: q, enabled: true, rows } satisfies ContactView);
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
