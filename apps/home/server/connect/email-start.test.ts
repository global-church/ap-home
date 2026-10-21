// One code per email while it is valid (Paul, 2026-10-15: "two emails with different codes").
import { beforeEach, describe, expect, it, vi } from 'vitest';

const sent: Array<{ to: string; code: string; replyTo?: string }> = [];
let lastApp: { name?: string; replyTo?: string } | undefined;
let failNext = false;
vi.mock('../_lib/home-sentry', async (orig) => ({ ...(await orig<object>()), reportHomeError: async () => {} }));
vi.mock('../_lib/email-sender', () => ({
  emailSendingEnabled: () => true,
  otpEmail: (to: string, code: string, _brand: string, app?: { name?: string; replyTo?: string }) => {
    lastApp = app;
    return { to, code, ...(app?.replyTo ? { replyTo: app.replyTo } : {}) };
  },
  sendEmail: async (_env: unknown, msg: { to: string; code: string }) => {
    if (failNext) {
      failNext = false;
      return { ok: false, error: 'Invalid email address: Invalid email domain' };
    }
    sent.push(msg);
    return { ok: true };
  },
}));

import { onRequestPost } from './email-start';

function kv() {
  const m = new Map<string, string>();
  return {
    get: async (k: string) => m.get(k) ?? null,
    put: async (k: string, v: string) => void m.set(k, v),
    delete: async (k: string) => void m.delete(k),
    m,
  };
}

const ask = (env: unknown, email = 'new.host@example.org', app?: string) =>
  onRequestPost({
    request: new Request('https://gcid.test/connect/email/start', { method: 'POST', body: JSON.stringify({ email, ...(app ? { app } : {}) }) }),
    env,
  } as never);

describe('POST /connect/email/start', () => {
  let env: { AUTH_CODES: ReturnType<typeof kv> };
  beforeEach(() => {
    sent.length = 0;
    failNext = false;
    env = { AUTH_CODES: kv() };
    vi.useRealTimers();
  });

  it('a double click sends ONE email', async () => {
    const [a, b] = await Promise.all([ask(env), ask(env)].map((p) => p.then((r) => r.json())));
    expect(a.ok && b.ok).toBe(true);
    // Both may race past the read, but they can only ever carry the same code.
    expect(new Set(sent.map((s) => s.code)).size).toBe(1);
  });

  it('a repeat within 30 seconds sends nothing more', async () => {
    await ask(env);
    await ask(env);
    expect(sent).toHaveLength(1);
  });

  it('Resend after 30 seconds sends the SAME code, so the first email still works', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date('2026-10-15T18:00:00Z'));
    await ask(env);
    vi.setSystemTime(new Date('2026-10-15T18:00:45Z'));
    await ask(env);
    expect(sent).toHaveLength(2);
    expect(sent[0]!.code).toBe(sent[1]!.code);
  });

  it('a different email gets its own code', async () => {
    await ask(env, 'a@example.org');
    await ask(env, 'b@example.org');
    expect(sent).toHaveLength(2);
  });

  it('a send that FAILED is not remembered as sent: retrying straight away sends (Ryan, 2026-10-15)', async () => {
    failNext = true;
    const first = await ask(env);
    expect(first.status).toBe(502);
    // The person sees a plain message, never the provider's text (Clayton, 2026-10-20).
    const body = (await first.json()) as { error: string; reason: string };
    expect(body.reason).toBe('send_failed');
    expect(body.error).toMatch(/couldn't send your code/);
    expect(body.error).not.toMatch(/Invalid email/);
    expect(sent).toHaveLength(0);
    await ask(env);
    expect(sent).toHaveLength(1);
  });

  it('the code email for a known relying app carries that app (its support inbox is the Reply-To); none for the portal — and the app NEVER becomes the code audience', async () => {
    await ask(env, 'a@example.org', 'gather-app');
    expect(lastApp, 'gather-app is in the registry').toBeTruthy();
    expect(lastApp?.name).toBeTruthy();
    const stored = JSON.parse(env.AUTH_CODES.m.values().next().value as string) as { aud: string };
    expect(stored.aud, 'custody eligibility at verify reads this').not.toBe('gather-app');
    lastApp = undefined;
    await ask(env, 'b@example.org');
    expect(lastApp).toBeUndefined();
  });
});
