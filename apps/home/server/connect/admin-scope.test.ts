// GCID Admin never reads which app a person or organization came through (Paul + Rich, 2026-10-27). In AP Home the
// app-scoped records (app-grants:, oidc-deleg:, delegated-idx:) and the link field that names the app (requestedBy)
// only scope an APP's own view. This fails if any Admin route reads them, or lets an app's name reach an answer.
import { readFileSync } from 'node:fs';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const A = (n: number) => `0x${String(n).padStart(40, '0')}`;
const OPERATOR = A(900), RYAN = A(1), HOST = A(10), ORG = A(20);
const BANNED_PREFIXES = ['app-grants:', 'oidc-deleg:', 'delegated-idx:'];
const APP_NAME = 'secret-app-name';

vi.mock('@agenticprimitives/connect', async (orig) => ({
  ...(await orig<object>()),
  importJwks: async () => [],
  verifyAgentSession: async (token: string) => (token.startsWith('tok:') ? { ok: true, session: { sub: `eip155:28190:${token.slice(4)}` } } : { ok: false, reason: 'bad' }),
}));
vi.mock('../_lib/server-broker', async (orig) => ({ ...(await orig<object>()), getServer: async () => ({ jwks: {} }), ownIssuer: () => 'https://gcid.test' }));
vi.mock('../_lib/verify-stewardship', () => ({
  verifyStewardship: async (_e: unknown, org: string, person: string, wire: { delegator?: string; delegate?: string } | undefined) =>
    org === OPERATOR && person === RYAN && wire?.delegator === OPERATOR && wire?.delegate === RYAN,
}));

import { onAdminAccounts, onAdminDirectory, onAdminMe, onAdminOrganizations, onAdminOrgTypes } from './admin';
import { resetOperatorAdminCache } from '../_lib/operator-directory';

let reads: string[] = [];
let env: never;

function kv(entries: Record<string, unknown>) {
  const m = new Map(Object.entries(entries).map(([k, v]) => [k, JSON.stringify(v)]));
  return {
    get: async (k: string) => { reads.push(k); return m.get(k) ?? null; },
    put: async (k: string, v: string) => void m.set(k, v),
    delete: async (k: string) => void m.delete(k),
    list: async ({ prefix }: { prefix: string }) => { reads.push(`list:${prefix}`); return { keys: [...m.keys()].filter((k) => k.startsWith(prefix)).map((name) => ({ name })), list_complete: true }; },
  };
}

beforeEach(() => {
  resetOperatorAdminCache();
  reads = [];
  env = {
    HOME_OPERATOR_ORG: OPERATOR,
    A2A_CUSTODY_URL: 'https://runtime.test',
    AUTH_CODES: kv({
      [`related:${RYAN}:${OPERATOR}`]: { stewardshipDelegation: { delegator: OPERATOR, delegate: RYAN, signature: '0xs', caveats: [] } },
      // An organization that came through an app: the link names the app.
      [`related:${HOST}:${ORG}`]: { orgName: 'grace.org', displayName: 'Grace Church', requestedBy: APP_NAME, kind: 'org', createdAt: 1 },
      'facet:email:h1': [{ agent: `eip155:28190:${HOST}`, assurance: 'verified', ref: 'kv-email' }],
      [`app-grants:${HOST}`]: [{ app: APP_NAME }],
      [`oidc-deleg:${HOST}:${APP_NAME}`]: { app: APP_NAME },
      [`delegated-idx:${HOST}`]: [APP_NAME],
    }),
  } as never;
  vi.stubGlobal('fetch', async (url: string) =>
    new Response(JSON.stringify(String(url).endsWith('/directory.masked') ? { ok: true, contacts: {} } : { ok: true, entries: [], requests: [] })));
});

const req = (path: string, body?: unknown) =>
  new Request(`https://gcid.test${path}`, { method: body ? 'POST' : 'GET', headers: { authorization: `Bearer tok:${RYAN}` }, ...(body ? { body: JSON.stringify(body) } : {}) });

describe('GCID Admin reads no app-scoped data', () => {
  it('no Admin route reads app-grants:, oidc-deleg: or delegated-idx:, and no answer names an app', async () => {
    const answers = await Promise.all([
      onAdminMe({ request: req('/connect/admin/me'), env }),
      onAdminAccounts({ request: req('/connect/admin/accounts'), env }),
      onAdminOrgTypes({ request: req('/connect/admin/org-types'), env }),
      onAdminOrganizations({ request: req('/connect/admin/organizations?app=all-accounts'), env }),
      onAdminOrganizations({ request: req('/connect/admin/organizations?app=all-organizations'), env }),
      onAdminDirectory({ request: req('/connect/admin/directory', { action: 'audit' }), env }),
      onAdminDirectory({ request: req('/connect/admin/directory', { action: 'export-list' }), env }),
    ]);
    for (const r of answers) expect(r.status).toBe(200);
    const banned = reads.filter((k) => BANNED_PREFIXES.some((p) => k.replace(/^list:/, '').startsWith(p)));
    expect(banned).toEqual([]);
    for (const r of answers) expect(await r.text()).not.toContain(APP_NAME);
  });

  it('the Admin code does not mention them at all', () => {
    // The server code that builds every Admin answer. (The page is covered by the test above: it only ever shows what
    // these answers carry. Its own "requested by" is an export request's field — the admin who asked — not an app.)
    for (const file of ['server/connect/admin.ts', 'src/lib/admin-stats.ts', 'server/_lib/operator-directory.ts']) {
      const src = readFileSync(new URL(`../../${file}`, import.meta.url), 'utf8');
      for (const word of [...BANNED_PREFIXES, 'requestedBy']) expect(src.includes(word), `${file} mentions ${word}`).toBe(false);
    }
  });
});
