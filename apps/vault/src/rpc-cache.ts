// THE VAULT'S CHAIN-READ CACHE (Global.Church, 2026-10-22).
//
// WHY. Verifying one delegation token makes 11–12 JSON-RPC reads (measured with Server-Timing on staging): is the
// delegator deployed (eth_getCode), is each signature valid (ERC-1271 isValidSignature / the universal validator's
// isValidSig, for the root and the session leaf), is anything revoked. Each read crosses from Cloudflare to the chain
// in Azure, ~170 ms, and they only partly overlap — about 1 s of every vault read or write, repeated for every op
// the same host makes. The RPC gateway caches eth_call for 2 s, which is why only the ops inside that window were fast.
//
// WHAT. A per-isolate cache in front of fetch for requests to the RPC URL, with a lifetime per kind of read:
//   - eth_getCode, non-empty:                         1 hour  (a deployed account does not become undeployed)
//   - isValidSignature / isValidSig, VALID:           10 min  (a valid signature stays valid; the one thing that
//                                                              changes it is a custody rotation, which is rare and
//                                                              is a deliberate act the owner makes)
//   - everything else (revocation reads, empty code): 2 s     (what the gateway already answers from its cache,
//                                                              so no staleness this deployment did not already have)
// Negative answers are never kept longer than 2 s: a refusal is re-asked. Identical reads in flight at the same
// moment share one request. Only the single-request JSON-RPC shape is cached; batches pass through.
//
// Revocation stays live (2 s, as before). ADR-0013: this is the same call with the same answer, remembered — not a
// second mechanism; a miss asks the chain exactly as before.
import { toFunctionSelector } from 'viem';

const SEL_IS_VALID_SIGNATURE = '0x1626ba7e'; // ERC-1271 isValidSignature(bytes32,bytes); the magic value is the same word
const SEL_IS_VALID_SIG = toFunctionSelector('isValidSig(address,bytes32,bytes)'); // UniversalSignatureValidator
const SEL_IS_VALID_SIG_WITH_SIDE_EFFECTS = toFunctionSelector('isValidSigWithSideEffects(address,bytes32,bytes)');

export const TTL = { CODE_MS: 60 * 60 * 1000, VALID_SIG_MS: 10 * 60 * 1000, SHORT_MS: 2_000 } as const;

interface Rpc { jsonrpc?: string; id?: unknown; method?: string; params?: unknown[] }
interface Entry { until: number; body: string }

const cache = new Map<string, Entry>();
const inflight = new Map<string, Promise<string>>();
export const stats = { hits: 0, misses: 0, shared: 0 };

/** The cache key for a single read, or null when the request is not one we cache. */
export function cacheKeyFor(rpc: Rpc): string | null {
  if (!rpc || typeof rpc.method !== 'string' || !Array.isArray(rpc.params)) return null;
  if (!['eth_call', 'eth_getCode', 'eth_chainId'].includes(rpc.method)) return null;
  const tag = rpc.params[rpc.params.length - 1];
  if (tag === 'pending') return null;
  return `${rpc.method}:${JSON.stringify(rpc.params)}`;
}

/** How long to keep this answer: by what was asked and what came back. */
export function ttlFor(rpc: Rpc, resultJson: string): number {
  let result: { result?: unknown; error?: unknown };
  try { result = JSON.parse(resultJson) as { result?: unknown; error?: unknown }; } catch { return 0; }
  if (result.error !== undefined || result.result === undefined || result.result === null) return 0; // never keep an error or nothing
  const r = String(result.result).toLowerCase();
  if (rpc.method === 'eth_chainId') return TTL.CODE_MS;
  if (rpc.method === 'eth_getCode') return r !== '0x' && r.length > 2 ? TTL.CODE_MS : TTL.SHORT_MS;
  if (rpc.method === 'eth_call') {
    const call = (rpc.params?.[0] ?? {}) as { data?: string; input?: string };
    const data = String(call.data ?? call.input ?? '').toLowerCase();
    const sel = data.slice(0, 10);
    if (sel === SEL_IS_VALID_SIGNATURE) {
      // bytes4 magic value, ABI-encoded left-aligned in a 32-byte word
      return r.startsWith(SEL_IS_VALID_SIGNATURE.slice(2), 2) ? TTL.VALID_SIG_MS : TTL.SHORT_MS;
    }
    if (sel === SEL_IS_VALID_SIG || sel === SEL_IS_VALID_SIG_WITH_SIDE_EFFECTS) {
      return /^0x0*1$/.test(r) ? TTL.VALID_SIG_MS : TTL.SHORT_MS; // bool true
    }
    return TTL.SHORT_MS;
  }
  return 0;
}

/** Wrap fetch so single JSON-RPC reads to `rpcHost` are answered from the cache when they can be. */
export function withRpcCache(origFetch: typeof fetch, rpcHost: string): typeof fetch {
  return (async (input: RequestInfo | URL, init?: RequestInit) => {
    let url = '';
    try { url = typeof input === 'string' ? input : input instanceof Request ? input.url : String(input); } catch { /* not ours */ }
    let host = '';
    try { host = new URL(url).host; } catch { /* not ours */ }
    const bodyText = typeof init?.body === 'string' ? init.body : null;
    if (host !== rpcHost || !bodyText || (init?.method ?? 'POST').toUpperCase() !== 'POST') return origFetch(input, init);
    let rpc: Rpc;
    try { rpc = JSON.parse(bodyText) as Rpc; } catch { return origFetch(input, init); }
    const key = cacheKeyFor(rpc);
    if (!key) return origFetch(input, init);
    const now = Date.now();
    const hit = cache.get(key);
    const reply = (body: string) => new Response(body.replace(/"id":\s*(?:"[^"]*"|\d+|null)/, `"id":${JSON.stringify(rpc.id ?? null)}`), { status: 200, headers: { 'content-type': 'application/json' } });
    if (hit && hit.until > now) { stats.hits++; return reply(hit.body); }
    const shared = inflight.get(key);
    if (shared) { stats.shared++; return reply(await shared); }
    stats.misses++;
    const p = (async () => {
      const res = await origFetch(input, init);
      const text = await res.text();
      if (res.ok) {
        const ttl = ttlFor(rpc, text);
        if (ttl > 0) cache.set(key, { until: Date.now() + ttl, body: text });
      }
      if (!res.ok) throw Object.assign(new Error(`rpc ${res.status}`), { status: res.status, text });
      return text;
    })();
    inflight.set(key, p);
    try {
      return reply(await p);
    } catch (e) {
      const err = e as { status?: number; text?: string };
      if (typeof err.status === 'number') return new Response(err.text ?? '', { status: err.status, headers: { 'content-type': 'application/json' } });
      throw e;
    } finally {
      inflight.delete(key);
      if (cache.size > 5000) { // keep the map bounded: drop what has expired, then the oldest
        for (const [k, v] of cache) if (v.until <= Date.now()) cache.delete(k);
        while (cache.size > 4000) { const k = cache.keys().next().value as string | undefined; if (k === undefined) break; cache.delete(k); }
      }
    }
  }) as typeof fetch;
}

/** For tests. */
export function resetRpcCache(): void { cache.clear(); inflight.clear(); stats.hits = 0; stats.misses = 0; stats.shared = 0; }
