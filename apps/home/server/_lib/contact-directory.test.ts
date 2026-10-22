import { describe, expect, it, vi } from 'vitest';

import { accountAddress, contactDirectoryEnabled, contactViews, readContactEmails, recordContactEmail, recordContactView } from './contact-directory';

const KEY = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))));
const A = '0x' + 'a'.repeat(40);
const B = '0x' + 'b'.repeat(40);
const ADMIN = '0x' + 'c'.repeat(40);

function kv() {
  const m = new Map<string, string>();
  return {
    m,
    get: async (k: string) => m.get(k) ?? null,
    put: async (k: string, v: string) => void m.set(k, v),
    delete: async (k: string) => void m.delete(k),
    list: async () => ({ keys: [...m.keys()].map((name) => ({ name })), list_complete: true }),
  };
}
const envWith = (store = kv(), key: string | undefined = KEY) => ({ AUTH_CODES: store, CONTACT_DIRECTORY_KEY: key }) as never;

describe('the operator contact directory (2026-10-21)', () => {
  it('keeps a verified address encrypted, and an admin can read it back', async () => {
    const store = kv();
    const env = envWith(store);
    await recordContactEmail(env, `eip155:28190:${A}`, ' Host@Church.org ', 'email-sign-in', 1000);
    const raw = store.m.get(`contact:${A}`)!;
    expect(raw).not.toContain('host@church.org'); // never stored readable
    expect((await readContactEmails(env, [A, B])).get(A)).toEqual({ email: 'host@church.org', verifiedAt: 1000, source: 'email-sign-in' });
  });

  it('records each view of the list: who, when, which listing, how many', async () => {
    const store = kv();
    const env = envWith(store);
    vi.spyOn(console, 'info').mockImplementation(() => {});
    await recordContactEmail(env, A, 'a@x.org', 'email-sign-in', 1);
    await recordContactEmail(env, A, 'new@x.org', 'email-sign-in', 30); // a newer verified address replaces the old
    expect((await readContactEmails(env, [A])).get(A)?.email).toBe('new@x.org');
    await recordContactView(store as never, { by: ADMIN.toUpperCase().replace('0X', '0x'), at: 10, what: 'organizations: gather-app', count: 1 });
    await recordContactView(store as never, { by: ADMIN, at: 20, what: 'organizations: gather-app', count: 2 });
    expect(await contactViews(store as never)).toEqual([
      { by: ADMIN, at: 20, what: 'organizations: gather-app', count: 2 },
      { by: ADMIN, at: 10, what: 'organizations: gather-app', count: 1 },
    ]);
  });

  it('a record cannot be moved onto another account', async () => {
    const store = kv();
    const env = envWith(store);
    await recordContactEmail(env, A, 'a@x.org', 'email-sign-in');
    store.m.set(`contact:${B}`, store.m.get(`contact:${A}`)!);
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    expect((await readContactEmails(env, [B])).has(B)).toBe(false);
  });

  it('a different key cannot read it', async () => {
    const store = kv();
    await recordContactEmail(envWith(store), A, 'a@x.org', 'email-sign-in');
    const other = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))));
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    expect((await readContactEmails(envWith(store, other), [A])).size).toBe(0);
  });

  it('with no key, nothing is kept and nothing fails', async () => {
    const store = kv();
    expect(contactDirectoryEnabled({ CONTACT_DIRECTORY_KEY: undefined })).toBe(false);
    expect(contactDirectoryEnabled({ CONTACT_DIRECTORY_KEY: 'short' })).toBe(false);
    await recordContactEmail(envWith(store, ''), A, 'a@x.org', 'email-sign-in');
    expect(store.m.size).toBe(0);
    expect((await readContactEmails(envWith(store, ''), [A])).size).toBe(0);
  });

  it('reads the address out of a canonical id', () => {
    expect(accountAddress(`eip155:28190:${A.toUpperCase().replace('0X', '0x')}`)).toBe(A);
    expect(accountAddress('nonsense')).toBeNull();
  });
});
