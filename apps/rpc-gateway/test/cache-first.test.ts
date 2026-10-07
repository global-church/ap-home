import { afterEach, describe, expect, it, vi } from 'vitest';
import gateway from '../src/index';

// The order this file pins (2026-10-07): token → allow-list → CACHE → rate limiter → origin. A HIT returns
// before the limiter (a Durable Object round trip per call); a MISS and every uncacheable call still pay it.
function harness(opts: { hit?: unknown; limited?: boolean } = {}) {
  const takes: unknown[] = [];
  const kvGets: unknown[] = [];
  const env = {
    ORIGIN: 'https://chain.example',
    TOKENS: { get: async (k: string, o: unknown) => { kvGets.push(o); return { app: 'a', readRps: 10, writeRps: 0 }; } },
    RATE: {
      idFromName: (n: string) => n,
      get: () => ({ fetch: async (_u: string, init: { body: string }) => { takes.push(JSON.parse(init.body)); return Response.json(opts.limited ? { ok: false, retryAfter: 1 } : { ok: true }); } }),
    },
  };
  vi.stubGlobal('caches', { default: {
    match: async () => (opts.hit === undefined ? undefined : Response.json({ result: opts.hit })),
    put: async () => undefined,
  } });
  vi.stubGlobal('fetch', vi.fn(async () => Response.json({ jsonrpc: '2.0', id: 1, result: '0x6e1e' })));
  const ctx = { waitUntil: () => undefined } as unknown as ExecutionContext;
  const call = (body: unknown) => gateway.fetch(new Request('https://gw/?k=tok', { method: 'POST', body: JSON.stringify(body) }), env as never, ctx);
  return { call, takes, kvGets };
}
const chainId = { jsonrpc: '2.0', id: 7, method: 'eth_chainId', params: [] };

afterEach(() => vi.unstubAllGlobals());

describe('cache before the rate limiter', () => {
  it('a HIT answers without touching the rate limiter or the origin', async () => {
    const h = harness({ hit: '0x6e1e' });
    const res = await h.call(chainId);
    expect(res.headers.get('x-cache')).toBe('HIT');
    expect(await res.json()).toEqual({ jsonrpc: '2.0', id: 7, result: '0x6e1e' });
    expect(h.takes).toHaveLength(0);
    expect(fetch).not.toHaveBeenCalled();
  });
  it('a MISS still pays the rate limiter before reaching the origin', async () => {
    const h = harness();
    const res = await h.call(chainId);
    expect(res.headers.get('x-cache')).toBe('MISS');
    expect(h.takes).toHaveLength(1);
    expect(fetch).toHaveBeenCalledTimes(1);
  });
  it('a limited MISS never reaches the origin', async () => {
    const h = harness({ limited: true });
    expect((await h.call(chainId)).status).toBe(429);
    expect(fetch).not.toHaveBeenCalled();
  });
  it('writes always pay the rate limiter', async () => {
    const h = harness({ hit: '0xdead' });
    await h.call({ jsonrpc: '2.0', id: 1, method: 'eth_sendRawTransaction', params: ['0x00'] });
    expect(h.takes).toEqual([{ reads: 0, writes: 1, readRps: 10, writeRps: 0 }]);
  });
  it('the token record is read with a 60 s edge cache', async () => {
    const h = harness({ hit: '0x6e1e' });
    await h.call(chainId);
    expect(h.kvGets[0]).toEqual({ type: 'json', cacheTtl: 60 });
  });
});
