import { describe, expect, it } from 'vitest';

import { countAccounts, countOrgs } from './admin-stats';
import { TEST_AGENT_PREFIX, agentAddress, isTestEmail, markTestAgent, testAddresses } from './test-identity';

const A = `0x${'a'.repeat(40)}`;
const T = `0x${'7'.repeat(40)}`;
const ORG = `0x${'b'.repeat(40)}`;
const TEST_ORG = `0x${'c'.repeat(40)}`;

describe('test identities (2026-10-20)', () => {
  it('the tag is the same rule as Gather’s', () => {
    expect(isTestEmail('chelsea+gcidtest@gathereverywhere.com')).toBe(true);
    expect(isTestEmail('Ryan+GCIDTEST2@gmail.com')).toBe(true);
    expect(isTestEmail('pastor+test@church.org')).toBe(false);
    expect(isTestEmail('gcidtest@church.org')).toBe(false);
    expect(isTestEmail(undefined)).toBe(false);
  });

  it('marks by address, once, keeping the first time', async () => {
    const store = new Map<string, string>();
    const kv = { get: async (k: string) => store.get(k) ?? null, put: async (k: string, v: string) => void store.set(k, v) };
    await markTestAgent(kv, `eip155:28190:${T.toUpperCase().replace('0X', '0x')}`, 1);
    await markTestAgent(kv, T, 2);
    expect([...store.keys()]).toEqual([`${TEST_AGENT_PREFIX}${T}`]);
    expect(JSON.parse(store.get(`${TEST_AGENT_PREFIX}${T}`)!)).toEqual({ since: 1 });
    expect(agentAddress('no address')).toBeNull();
  });

  it('the Admin counts leave test people, and orgs only they link to, out', () => {
    const tests = testAddresses([`${TEST_AGENT_PREFIX}${T}`, 'facet:email:x']);
    const facets = [
      { key: 'facet:email:1', value: JSON.stringify({ agent: `eip155:28190:${A}`, assurance: 'asserted', ref: 'kv-email' }) },
      { key: 'facet:email:2', value: JSON.stringify({ agent: `eip155:28190:${T}`, assurance: 'asserted', ref: 'kv-email' }) },
    ];
    expect(countAccounts(facets, tests)).toMatchObject({ accounts: 1, testAccounts: 1 });
    expect(countAccounts(facets)).toMatchObject({ accounts: 2, testAccounts: 0 });
    const links = [
      { key: `related:${A}:${ORG}`, value: JSON.stringify({ kind: 'org', createdAt: 0 }) },
      { key: `related:${T}:${ORG}`, value: JSON.stringify({ kind: 'org', createdAt: 0 }) },
      { key: `related:${T}:${TEST_ORG}`, value: JSON.stringify({ kind: 'org', createdAt: 0 }) },
    ];
    expect(countOrgs(links, 10, tests).organizations).toBe(1);
    expect(countOrgs(links, 10).organizations).toBe(2);
  });
});
