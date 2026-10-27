import { afterEach, describe, expect, it, vi } from 'vitest';
import gateway from '../src/index';
import { browserRefusal, stripBlockTransactions, BROWSER_DENIED_SELECTORS } from '../src/config';

// A token in a web page reads what it can name; it never lists what the chain holds (2026-10-27).
const REGISTRY = '0x' + '11'.repeat(20);
const ACCOUNT = '0x' + '22'.repeat(20);
const call = (method: string, params: unknown[] = []) => ({ jsonrpc: '2.0', id: 1, method, params });
const ethCall = (data: string, extra: unknown[] = ['latest'], to: string | null = REGISTRY) => call('eth_call', [{ ...(to ? { to } : {}), data }, ...extra]);
// childLabelhashes(bytes32) on a node, and the same call wrapped as the inner bytes of an account's execute().
const LIST_CHILDREN = '0x3002c03b' + 'ab'.repeat(32);
const EXECUTE_WRAPPED = '0xb61d27f6' + '00'.repeat(12) + '11'.repeat(20) + '00'.repeat(32) + '00'.repeat(31) + '60' + '00'.repeat(31) + '24' + LIST_CHILDREN.slice(2) + '00'.repeat(28);
// A name lookup the website makes (any selector not on the list).
const RESOLVE = '0x0178b8bf' + 'cd'.repeat(32);

describe('what a browser token may not do', () => {
  it('no logs, block receipts, filters or raw storage', () => {
    for (const m of ['eth_getLogs', 'eth_getBlockReceipts', 'eth_getStorageAt', 'eth_newFilter', 'eth_getFilterLogs', 'eth_getFilterChanges']) {
      expect(browserRefusal(call(m)), m).not.toBeNull();
    }
  });
  it('no listing function, called directly or wrapped inside another call', () => {
    expect(browserRefusal(ethCall(LIST_CHILDREN))).toMatch(/childLabelhashes/);
    expect(browserRefusal({ ...ethCall(EXECUTE_WRAPPED), params: [{ to: ACCOUNT, from: '0x' + '33'.repeat(20), data: EXECUTE_WRAPPED }, 'latest'] })).toMatch(/childLabelhashes/);
    for (const sel of Object.keys(BROWSER_DENIED_SELECTORS)) expect(browserRefusal(ethCall('0x' + sel)), sel).not.toBeNull();
  });
  it('no call without a target, and no state override (both run the caller’s own code)', () => {
    expect(browserRefusal(ethCall(RESOLVE, ['latest'], null))).toMatch(/contract address/);
    expect(browserRefusal(ethCall(RESOLVE, ['latest', { [REGISTRY]: { code: '0x00' } }]))).toMatch(/state overrides/);
    expect(browserRefusal(call('eth_estimateGas', [{ data: '0x6000' }]))).toMatch(/contract address/);
  });
  it('the reads the website makes stay open', () => {
    expect(browserRefusal(ethCall(RESOLVE))).toBeNull();
    for (const m of ['eth_chainId', 'eth_blockNumber', 'eth_getCode', 'eth_getBalance', 'eth_getTransactionReceipt', 'eth_getBlockByNumber']) {
      expect(browserRefusal(call(m, ['0x1'])), m).toBeNull();
    }
  });
  it('a block loses its transaction list, keeps the rest', () => {
    expect(stripBlockTransactions('eth_getBlockByNumber', { number: '0x5', timestamp: '0x9', transactions: ['0xaa', '0xbb'] })).toEqual({ number: '0x5', timestamp: '0x9', transactions: [] });
    expect(stripBlockTransactions('eth_call', '0x01')).toBe('0x01');
  });
});

function harness(scope: 'browser' | undefined, originResult: unknown) {
  const env = {
    ORIGIN: 'https://chain.example',
    TOKENS: { get: async () => ({ app: 'web', readRps: 10, writeRps: 0, ...(scope ? { scope } : {}) }) },
    RATE: { idFromName: (n: string) => n, get: () => ({ fetch: async () => Response.json({ ok: true }) }) },
  };
  vi.stubGlobal('caches', { default: { match: async () => undefined, put: async () => undefined } });
  vi.stubGlobal('fetch', vi.fn(async (_u: string, init: { body: string }) => {
    const b = JSON.parse(init.body) as { id: unknown } | { id: unknown }[];
    const one = (x: { id: unknown }) => ({ jsonrpc: '2.0', id: x.id, result: originResult });
    return Response.json(Array.isArray(b) ? b.map(one) : one(b));
  }));
  const ctx = { waitUntil: () => undefined } as unknown as ExecutionContext;
  return (body: unknown) => gateway.fetch(new Request('https://gw/?k=tok', { method: 'POST', body: JSON.stringify(body) }), env as never, ctx);
}
afterEach(() => vi.unstubAllGlobals());

describe('through the gateway', () => {
  it('a browser token is refused a listing call before it reaches the chain', async () => {
    const send = harness('browser', '0x');
    const res = await send(ethCall(LIST_CHILDREN));
    expect(res.status).toBe(403);
    expect(fetch).not.toHaveBeenCalled();
  });
  it('a browser token gets blocks without transactions, single and in a batch', async () => {
    const block = { number: '0x5', transactions: ['0xaa'] };
    const send = harness('browser', block);
    expect(((await (await send(call('eth_getBlockByNumber', ['latest', false]))).json()) as { result: { transactions: unknown[] } }).result.transactions).toEqual([]);
    const batch = (await (await send([call('eth_getBlockByNumber', ['latest', true]), { ...call('eth_getBlockByHash', ['0x01', false]), id: 2 }])).json()) as { result: { transactions: unknown[] } }[];
    expect(batch.map((r) => r.result.transactions)).toEqual([[], []]);
  });
  it('a server token is unchanged: logs and listings still work, blocks keep their transactions', async () => {
    const send = harness(undefined, { number: '0x5', transactions: ['0xaa'] });
    expect((await send(call('eth_getLogs', [{}]))).status).toBe(200);
    expect((await send(ethCall(LIST_CHILDREN))).status).toBe(200);
    expect(((await (await send(call('eth_getBlockByNumber', ['latest', false]))).json()) as { result: { transactions: unknown[] } }).result.transactions).toEqual(['0xaa']);
  });
});
