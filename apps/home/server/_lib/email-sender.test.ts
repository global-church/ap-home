import { afterEach, describe, expect, it, vi } from 'vitest';

import { sendEmail } from './email-sender';

// Reply-To on system mail (Gather, 2026-10-09): a host invite Home sends for an app should be answered in the
// app's own inbox, so the address rides the bridge payload to the Worker that actually sends.
const env = { A2A_CUSTODY_URL: 'https://runtime.example', A2A_CUSTODY_BRIDGE_SECRET: 'bridge-secret-for-tests' };

function capture() {
  const bodies: Record<string, unknown>[] = [];
  vi.stubGlobal('fetch', vi.fn(async (_url: string, init: RequestInit) => {
    bodies.push(JSON.parse(String(init.body)));
    return new Response(JSON.stringify({ ok: true }), { status: 200, headers: { 'content-type': 'application/json' } });
  }));
  return bodies;
}

afterEach(() => vi.unstubAllGlobals());

describe('sendEmail Reply-To', () => {
  it('carries replyTo to the Worker when set', async () => {
    const bodies = capture();
    const r = await sendEmail(env, { to: 'host@church.org', subject: 's', html: '<p>x</p>', text: 'x', replyTo: 'gathergroups@gathereverywhere.com' });
    expect(r.ok).toBe(true);
    expect(JSON.stringify(bodies[0])).toContain('gathergroups@gathereverywhere.com');
  });

  it('sends no replyTo when none is set (every other mail, unchanged)', async () => {
    const bodies = capture();
    await sendEmail(env, { to: 'host@church.org', subject: 's', html: '<p>x</p>', text: 'x' });
    expect(JSON.stringify(bodies[0])).not.toContain('replyTo');
  });
});
