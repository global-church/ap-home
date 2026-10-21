import { describe, expect, it } from 'vitest';
import { countAccounts, countOrgs, growth, tallyOrgTypes, isAdmin, methodOf, parseAdmins, recordSnapshot, type Snapshot } from './admin-stats';

const A = '0x' + 'a'.repeat(40);
const B = '0x' + 'b'.repeat(40);
const C = '0x' + 'c'.repeat(40);
const sa = (a: string) => `eip155:28190:${a}`;
const link = (agent: string, ref = 'kv-email') => ({ agent: sa(agent), assurance: 'asserted', ref });

describe('who is an admin', () => {
  it('reads the list, ignoring anything that is not an address', () => {
    expect([...parseAdmins(` ${A.toUpperCase().replace('0X', '0x')} , nope, ${B}`)]).toEqual([A, B]);
  });
  it('an empty or unset list is nobody', () => {
    expect(isAdmin(sa(A), parseAdmins(undefined))).toBe(false);
    expect(isAdmin(sa(A), parseAdmins(''))).toBe(false);
  });
  it('matches the session subject address, case-insensitively', () => {
    const admins = parseAdmins(A);
    expect(isAdmin(sa(A.toUpperCase().replace('0X', '0x')), admins)).toBe(true);
    expect(isAdmin(sa(B), admins)).toBe(false);
    expect(isAdmin('not-an-address', admins)).toBe(false);
  });
});

describe('counting GCID accounts', () => {
  it('classifies facet keys by sign-in method', () => {
    expect(methodOf('facet:email:abc')).toBe('email');
    expect(methodOf('facet:phone:abc')).toBe('phone');
    expect(methodOf('facet:oidc:https://accounts.google.com#123')).toBe('google');
    expect(methodOf('facet:oidc:https://login.youversion.com#1')).toBe('other');
    expect(methodOf('facet:cred:passkey:digest')).toBe('passkey');
  });

  it('a person with two ways to sign in counts once', () => {
    const r = countAccounts([
      { key: 'facet:email:h1', value: JSON.stringify([link(A)]) },
      { key: 'facet:cred:passkey:d1', value: JSON.stringify([link(A, 'kv-cred')]) },
      { key: 'facet:email:h2', value: JSON.stringify([link(B)]) },
    ]);
    expect(r.accounts).toBe(2);
    expect(r.byMethod.email).toBe(2);
    expect(r.byMethod.passkey).toBe(1);
  });

  it('an unlinked (tombstoned) facet does not count; a legacy single object and junk are handled', () => {
    const r = countAccounts([
      { key: 'facet:email:h1', value: JSON.stringify([link(A), { agent: sa(A), assurance: 'unverified', ref: 'tombstone:kv-email' }]) },
      { key: 'facet:phone:h2', value: JSON.stringify(link(C, 'kv-phone')) },
      { key: 'facet:email:h3', value: 'not json' },
      { key: 'facet:email:h4', value: null },
    ]);
    expect(r.accounts).toBe(1);
    expect(r.byMethod.email).toBe(0);
    expect(r.byMethod.phone).toBe(1);
  });
});

describe('counting organizations', () => {
  const now = Date.UTC(2026, 9, 9);
  const day = 24 * 3600 * 1000;
  it('counts distinct orgs, separates workspaces, leaves out a person\'s own other names and deleted orgs', () => {
    const r = countOrgs([
      { key: `related:${A}:${B}`, value: JSON.stringify({ kind: 'org', createdAt: now - 2 * day }) },
      { key: `related:${C}:${B}`, value: JSON.stringify({ kind: 'org', createdAt: now - 40 * day }) },
      { key: `related:${A}:${C}`, value: JSON.stringify({ kind: 'workspace', createdAt: now - day }) },
      { key: `related:${A}:0x${'d'.repeat(40)}`, value: JSON.stringify({ kind: 'person', relationship: 'self' }) },
      { key: `related:${A}:0x${'e'.repeat(40)}`, value: JSON.stringify({ kind: 'org', status: 'deleted' }) },
    ], now);
    expect(r).toEqual({ organizations: 1, workspaces: 1, newOrganizations7d: 0, newOrganizations30d: 0 });
  });
});

describe('growth from daily snapshots', () => {
  const now = Date.UTC(2026, 9, 9, 15);
  it('is unknown until the history reaches back far enough', () => {
    const h = recordSnapshot([], { date: '2026-10-09', accounts: 10, organizations: 2 });
    expect(growth(h, now, 7, 'accounts')).toBeNull();
  });
  it('is today minus the snapshot from that many days ago', () => {
    let h: Snapshot[] = [{ date: '2026-10-01', accounts: 4, organizations: 1 }, { date: '2026-10-02', accounts: 6, organizations: 1 }];
    h = recordSnapshot(h, { date: '2026-10-09', accounts: 10, organizations: 2 });
    h = recordSnapshot(h, { date: '2026-10-09', accounts: 11, organizations: 2 });
    expect(h).toHaveLength(3);
    expect(growth(h, now, 7, 'accounts')).toBe(5);
  });
});

describe('organization types (2026-10-21)', () => {
  const P = '0x' + '1'.repeat(40), Q = '0x' + '2'.repeat(40), T = '0x' + '3'.repeat(40);
  const O1 = '0x' + 'd'.repeat(40), O2 = '0x' + 'e'.repeat(40), O3 = '0x' + 'f'.repeat(40), O4 = '0x' + '9'.repeat(40), W = '0x' + '8'.repeat(40);
  const CHR = { iri: 'https://ontology.global.church/core#organizationtypevalue-chr', label: 'Church' };
  const l = (person: string, org: string, v: object) => ({ key: `related:${person}:${org}`, value: JSON.stringify(v) });

  it('counts each organization once, lists Other answers in the steward’s words, and counts the untyped', () => {
    const r = tallyOrgTypes([
      l(P, O1, { kind: 'org', createdAt: 1, orgType: CHR }),
      l(Q, O1, { kind: 'org', createdAt: 2 }), // a second steward of the same church
      l(P, O2, { kind: 'org', createdAt: 5, orgType: { iri: null, label: 'Other', other: 'House church network' } }),
      l(P, O3, { kind: 'org', createdAt: 3 }), // created before the question existed
      l(P, W, { kind: 'workspace', orgType: CHR }),
      l(P, P, { kind: 'person', relationship: 'self' }),
      l(T, O4, { kind: 'org', orgType: CHR }), // a test identity's org
    ], new Set([T]));
    expect(r.byType).toEqual([{ ...CHR, count: 1 }]);
    expect(r.other).toEqual([{ text: 'House church network', at: 5 }]);
    expect(r.noType).toBe(1);
  });

  it('leaves deleted organizations and unreadable links out', () => {
    const r = tallyOrgTypes([l(P, O1, { kind: 'org', status: 'deleted', orgType: CHR }), { key: `related:${P}:${O2}`, value: '{' }]);
    expect(r).toEqual({ byType: [], other: [], noType: 0 });
  });
});
