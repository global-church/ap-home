import { describe, expect, it } from 'vitest';
import { isSealed, makeSealer, type Envelope, type StoredDek } from '../src/directory-seal';

// A fake key service: "wraps" by XOR with a fixed byte, and checks the AAD it is given each time.
function fakeEnvelope() {
  const calls = { generate: 0, unwrap: 0, aad: [] as string[] };
  const env: Envelope = {
    async generate(aad) {
      calls.generate++; calls.aad.push(JSON.stringify(aad));
      const plaintext = crypto.getRandomValues(new Uint8Array(32));
      return { plaintext: plaintext.slice(), wrapped: plaintext.map((b) => b ^ 0x5a), keyId: 'k1', keyVersion: '1' };
    },
    async unwrap(d, aad) {
      calls.unwrap++; calls.aad.push(JSON.stringify(aad));
      if (aad.workspace !== WS) throw new Error('aad mismatch');
      return d.wrapped.map((b) => b ^ 0x5a);
    },
  };
  return { env, calls };
}
function memStore() {
  let d: StoredDek | undefined;
  return { get: async () => d, put: async (x: StoredDek) => { d = x; }, peek: () => d };
}
const WS = '0x' + '77'.repeat(20);
const A = '0x' + '01'.repeat(20);
const B = '0x' + '02'.repeat(20);

describe('the directory seal', () => {
  it('seals to ciphertext that opens back to the email', async () => {
    const { env } = fakeEnvelope();
    const s = makeSealer({ workspace: WS, store: memStore(), envelope: env });
    const sealed = await s.seal(A, 'pastor@grace.org');
    expect(isSealed(sealed)).toBe(true);
    expect(sealed).not.toContain('pastor');
    expect(await s.open(A, sealed)).toBe('pastor@grace.org');
  });
  it('a sealed value is bound to its record: it does not open as another account', async () => {
    const { env } = fakeEnvelope();
    const s = makeSealer({ workspace: WS, store: memStore(), envelope: env });
    const sealed = await s.seal(A, 'pastor@grace.org');
    await expect(s.open(B, sealed)).rejects.toThrow();
  });
  it('generates ONE data key, keeps only its wrapped copy, and reuses it (unwrapping after a restart)', async () => {
    const { env, calls } = fakeEnvelope();
    const store = memStore();
    const s1 = makeSealer({ workspace: WS, store, envelope: env });
    await Promise.all([s1.seal(A, 'a@x.org'), s1.seal(B, 'b@x.org')]);
    expect(calls.generate).toBe(1);
    expect(store.peek()).toMatchObject({ keyId: 'k1', keyVersion: '1' });
    const sealed = await s1.seal(A, 'a@x.org');
    // A new instance (the DO restarted) unwraps the stored key; it never generates a second one.
    const s2 = makeSealer({ workspace: WS, store, envelope: env });
    expect(await s2.open(A, sealed)).toBe('a@x.org');
    expect(calls.generate).toBe(1);
    expect(calls.unwrap).toBe(1);
    expect(calls.aad.every((a) => a.includes('"purpose":"operator-directory"'))).toBe(true);
  });
  it('re-unwraps after the in-memory key expires', async () => {
    const { env, calls } = fakeEnvelope();
    const store = memStore();
    let t = 0;
    await makeSealer({ workspace: WS, store, envelope: env, now: () => t }).seal(A, 'a@x.org');
    const s = makeSealer({ workspace: WS, store, envelope: env, now: () => t });
    await s.seal(A, 'a@x.org');
    t += 11 * 60 * 1000;
    await s.seal(A, 'a@x.org');
    expect(calls.unwrap).toBe(2);
  });
});
