import { beforeEach, describe, expect, it, vi } from 'vitest';
import { toFunctionSelector } from 'viem';

import { cacheKeyFor, resetRpcCache, stats, TTL, ttlFor, withRpcCache } from '../src/rpc-cache';

const RPC = 'https://home-rpc-staging.gcid.io/?k=abc';
const USV = '0x' + 'f'.repeat(40);
const isValidSig = toFunctionSelector('isValidSig(address,bytes32,bytes)');
const call = (data: string, id = 1) => JSON.stringify({ jsonrpc: '2.0', id, method: 'eth_call', params: [{ to: USV, data }, 'latest'] });
const TRUE = '0x' + '0'.repeat(63) + '1';
const FALSE = '0x' + '0'.repeat(64);
const MAGIC = '0x1626ba7e' + '0'.repeat(56);

function fakeChain(answers: Record<string, string>) {
  const calls: string[] = [];
  const f = (async (_input: RequestInfo | URL, init?: RequestInit) => {
    const rpc = JSON.parse(String(init?.body)) as { id: number; method: string; params: unknown[] };
    calls.push(rpc.method);
    const data = rpc.method === 'eth_call' ? ((rpc.params[0] as { data: string }).data) : rpc.method === 'eth_getCode' ? 'code:' + rpc.params[0] : rpc.method;
    const key = Object.keys(answers).find((k) => data.startsWith(k)) ?? '';
    await new Promise((r) => setTimeout(r, 5));
    return new Response(JSON.stringify({ jsonrpc: '2.0', id: rpc.id, result: answers[key] ?? FALSE }), { status: 200 });
  }) as typeof fetch;
  return { fetch: withRpcCache(f, new URL(RPC).host), calls };
}

beforeEach(() => resetRpcCache());

describe('what is cached, and for how long', () => {
  it('a deployed account stays deployed; an empty answer is re-asked', () => {
    const code = { method: 'eth_getCode', params: ['0x' + 'a'.repeat(40), 'latest'] };
    expect(ttlFor(code, JSON.stringify({ result: '0x6080' }))).toBe(TTL.CODE_MS);
    expect(ttlFor(code, JSON.stringify({ result: '0x' }))).toBe(TTL.SHORT_MS);
  });
  it('a VALID signature is kept ten minutes; an invalid one two seconds', () => {
    const usv = { method: 'eth_call', params: [{ to: USV, data: isValidSig + 'ab' }, 'latest'] };
    expect(ttlFor(usv, JSON.stringify({ result: TRUE }))).toBe(TTL.VALID_SIG_MS);
    expect(ttlFor(usv, JSON.stringify({ result: FALSE }))).toBe(TTL.SHORT_MS);
    const erc1271 = { method: 'eth_call', params: [{ to: USV, data: '0x1626ba7e' + 'cd' }, 'latest'] };
    expect(ttlFor(erc1271, JSON.stringify({ result: MAGIC }))).toBe(TTL.VALID_SIG_MS);
    expect(ttlFor(erc1271, JSON.stringify({ result: FALSE }))).toBe(TTL.SHORT_MS);
  });
  it('any other read (a revocation check) keeps the gateway’s two seconds; errors are never kept', () => {
    const other = { method: 'eth_call', params: [{ to: USV, data: '0x12345678' }, 'latest'] };
    expect(ttlFor(other, JSON.stringify({ result: TRUE }))).toBe(TTL.SHORT_MS);
    expect(ttlFor(other, JSON.stringify({ error: { code: -32000 } }))).toBe(0);
    expect(cacheKeyFor({ method: 'eth_sendRawTransaction', params: ['0x'] })).toBeNull();
    expect(cacheKeyFor({ method: 'eth_call', params: [{}, 'pending'] })).toBeNull();
  });
});

describe('the wrapped fetch', () => {
  it('asks the chain once for a valid signature, then answers from memory with the caller’s id', async () => {
    const chain = fakeChain({ [isValidSig]: TRUE });
    const a = await (await chain.fetch(RPC, { method: 'POST', body: call(isValidSig + '01', 7) })).json();
    const b = await (await chain.fetch(RPC, { method: 'POST', body: call(isValidSig + '01', 8) })).json();
    expect(chain.calls).toEqual(['eth_call']);
    expect(a).toEqual({ jsonrpc: '2.0', id: 7, result: TRUE });
    expect(b).toEqual({ jsonrpc: '2.0', id: 8, result: TRUE });
    expect(stats).toMatchObject({ hits: 1, misses: 1 });
  });
  it('identical reads in flight share one request', async () => {
    const chain = fakeChain({ 'code:': '0x6080' });
    const body = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_getCode', params: ['0x' + 'b'.repeat(40), 'latest'] });
    await Promise.all([1, 2, 3].map(() => chain.fetch(RPC, { method: 'POST', body })));
    expect(chain.calls).toEqual(['eth_getCode']);
    expect(stats.shared).toBe(2);
  });
  it('leaves other hosts, writes and batches alone', async () => {
    const chain = fakeChain({});
    await chain.fetch('https://akcs-staging.gcid.io/sign', { method: 'POST', body: '{"x":1}' }).catch(() => undefined);
    await chain.fetch(RPC, { method: 'POST', body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_sendRawTransaction', params: ['0x00'] }) });
    await chain.fetch(RPC, { method: 'POST', body: JSON.stringify([{ jsonrpc: '2.0', id: 1, method: 'eth_chainId', params: [] }]) }).catch(() => undefined);
    expect(stats).toMatchObject({ hits: 0, misses: 0 });
  });
});

describe('a read the chain did not answer (2026-10-22)', () => {
  it('is asked once more, and the second answer is the one returned', async () => {
    let n = 0;
    const flaky = (async (_i: RequestInfo | URL, init?: RequestInit) => {
      n++;
      const rpc = JSON.parse(String(init?.body)) as { id: number };
      if (n === 1) return new Response('upstream timeout', { status: 503 });
      return new Response(JSON.stringify({ jsonrpc: '2.0', id: rpc.id, result: TRUE }), { status: 200 });
    }) as typeof fetch;
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    const f = withRpcCache(flaky, new URL(RPC).host);
    const out = await (await f(RPC, { method: 'POST', body: call(isValidSig + '02', 4) })).json();
    expect(n).toBe(2);
    expect(out).toEqual({ jsonrpc: '2.0', id: 4, result: TRUE });
  });
  it('a revert is a real answer and is not asked again', async () => {
    let n = 0;
    const reverting = (async (_i: RequestInfo | URL, init?: RequestInit) => {
      n++;
      const rpc = JSON.parse(String(init?.body)) as { id: number };
      return new Response(JSON.stringify({ jsonrpc: '2.0', id: rpc.id, error: { code: 3, message: 'execution reverted' } }), { status: 200 });
    }) as typeof fetch;
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    await withRpcCache(reverting, new URL(RPC).host)(RPC, { method: 'POST', body: call(isValidSig + '03') });
    expect(n).toBe(1);
  });
  it('two failures return the failure, as before', async () => {
    const down = (async () => new Response('nope', { status: 502 })) as typeof fetch;
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    const r = await withRpcCache(down, new URL(RPC).host)(RPC, { method: 'POST', body: call(isValidSig + '04') });
    expect(r.status).toBe(502);
  });
});
