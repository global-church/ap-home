// TEST IDENTITIES (Global.Church, 2026-10-20; agreed with Gather's Paul Martel and Clayton Fike).
//
// People who test on PRODUCTION sign in with their own mailbox plus a fixed tag: `chelsea+gcidtest@…` (a suffix
// such as `+gcidtest2` counts too). A plus address hashes to a different email facet, so a tester is a separate
// GCID person from their real account.
//
// The Home never stores an email address (kv-indexer.ts keys facets by SHA-256), so the tag cannot be found
// afterwards: it is read ONCE, at sign-in, while the address is in hand, and the person is marked
// (`test-agent:<address>`). The Admin tab's counts leave marked people out, and organizations only they link to.
// Nothing else treats them differently: they sign in, publish and are served like anyone else.
//
// The same rule, word for word, is Gather's: engage packages/gather-domain/src/test-identity.ts.

export const TEST_EMAIL_TAG = 'gcidtest';
export const TEST_AGENT_PREFIX = 'test-agent:';

/** Whether an email address carries the test tag in its local part (`name+gcidtest…@domain`). */
export function isTestEmail(email: string | null | undefined): boolean {
  const e = (email ?? '').trim().toLowerCase();
  const at = e.lastIndexOf('@');
  if (at <= 0) return false;
  return e.slice(0, at).split('+').slice(1).some((part) => part.startsWith(TEST_EMAIL_TAG));
}

/** The 0x address at the end of an agent id (`eip155:<chain>:0x…` or a bare address), lower case. */
export function agentAddress(agent: string): string | null {
  return agent.match(/0x[0-9a-fA-F]{40}$/)?.[0]?.toLowerCase() ?? null;
}

/** Mark a person as a test identity. Idempotent; keeps the first time it was seen. */
export async function markTestAgent(
  kv: { get(key: string): Promise<string | null>; put(key: string, value: string): Promise<void> },
  agent: string,
  now = Date.now(),
): Promise<void> {
  const address = agentAddress(agent);
  if (!address) return;
  const key = `${TEST_AGENT_PREFIX}${address}`;
  if (await kv.get(key)) return;
  await kv.put(key, JSON.stringify({ since: now }));
}

/** `test-agent:` keys → the set of marked addresses. */
export function testAddresses(keys: readonly string[]): Set<string> {
  return new Set(keys.filter((k) => k.startsWith(TEST_AGENT_PREFIX)).map((k) => k.slice(TEST_AGENT_PREFIX.length).toLowerCase()));
}
