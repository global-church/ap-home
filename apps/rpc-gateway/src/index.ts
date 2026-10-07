// Chain RPC gateway: token auth → method allow-list → gas-cap inject → per-app rate limit → read cache →
// forward to the private origin. Generic over the chain; every hostname lives in wrangler.toml [env.*].
import { isAllowed, isWrite, CACHE_TTL_S, injectEstimateGasCap, type Rpc } from './config';
export { RateLimiter } from './ratelimit';
// ORIGIN_CLIENT_ID / ORIGIN_CLIENT_SECRET are secrets (`wrangler secret put`), never vars. They are what
// this gateway presents TO its origin. TOKENS answers "may this caller use the chain"; this pair answers
// "is this request really from the gateway". Without it, publishing the origin on a hostname makes the
// token check decorative — anyone who learns the hostname skips the allow-list, the gas cap and the rate
// limiter and talks to the node directly. On a free-gas chain that is an invitation to bloat the state,
// not just a read leak. Unset is allowed: a VNet-private origin needs no second factor, and an estate
// whose origin is fronted by Cloudflare Access sets the pair and nothing else changes.
interface Env { TOKENS: KVNamespace; RATE: DurableObjectNamespace; ORIGIN: string; ESTIMATE_GAS_CAP?: string; ORIGIN_CLIENT_ID?: string; ORIGIN_CLIENT_SECRET?: string; }
const err = (id: unknown, code: number, message: string, status = 200) =>
  new Response(JSON.stringify({ jsonrpc: '2.0', id: id ?? null, error: { code, message } }), { status, headers: { 'content-type': 'application/json' } });
/** How long a colo may reuse a token record it read from KV. Also the bound on how long a REVOKED token
 *  keeps working at a colo that had just read it (approved by Global.Church, 2026-10-07). */
export const TOKEN_CACHE_TTL_S = 60;
const sha256 = async (s: string) => [...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s)))].map(b => b.toString(16).padStart(2, '0')).join('');
// Cloudflare Access service-token header names — also ordinary headers, so an origin fronted some other
// way (nginx, say) can check the same pair without Access being involved.
export const originHeaders = (env: Pick<Env, 'ORIGIN_CLIENT_ID' | 'ORIGIN_CLIENT_SECRET'>): Record<string, string> => {
  const h: Record<string, string> = { 'content-type': 'application/json' };
  if (env.ORIGIN_CLIENT_ID && env.ORIGIN_CLIENT_SECRET) { h['CF-Access-Client-Id'] = env.ORIGIN_CLIENT_ID; h['CF-Access-Client-Secret'] = env.ORIGIN_CLIENT_SECRET; }
  return h;
};
const forward = (env: Env, body: unknown) => fetch(env.ORIGIN, { method: 'POST', headers: originHeaders(env), body: JSON.stringify(body) })
  .then(u => new Response(u.body, { status: u.status, headers: { 'content-type': 'application/json' } }));
/** The read-cache key. caches.default is shared by EVERY Worker on the zone, so a key without the origin
 *  lets two gateways on one zone — two estates, or two chains — answer from each other's entries: a
 *  staging gateway's cached eth_chainId was served by production's (found 2026-10-06). The origin is the
 *  chain this gateway forwards to, so it is exactly the scope a cached answer is true for. */
export function cacheKey(origin: string, method: string, paramsHash: string): string {
  return `https://cache/${encodeURIComponent(new URL(origin).host)}/${method}/${paramsHash}`;
}

export default {
  async fetch(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    // CORS: browser apps call this RPC directly for read-only eth_call. Auth is the ?k= URL token,
    // never a cookie, so reflecting the Origin is safe — a stolen response is read-only and the token
    // already gates it.
    const origin = req.headers.get('Origin') || '*';
    const cors: Record<string, string> = {
      'access-control-allow-origin': origin,
      'vary': 'Origin',
      'access-control-allow-methods': 'POST, OPTIONS',
      'access-control-allow-headers': 'authorization, content-type',
      'access-control-max-age': '86400',
    };
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });

    const run = async (): Promise<Response> => {
      if (req.method !== 'POST') return new Response('POST JSON-RPC only', { status: 405 });
      if (!env.ORIGIN) return err(null, -32603, 'gateway misconfigured: ORIGIN unset', 500);
      // Auth: Bearer header (header-capable clients) OR ?k=<token> in the URL (header-less clients —
      // a viem RPC client in the browser, forge). A token baked into a browser bundle is issued with
      // writeRps 0, so it can only read.
      const bearer = (req.headers.get('authorization') || '').replace(/^Bearer\s+/i, '').trim()
        || new URL(req.url).searchParams.get('k') || '';
      if (!bearer) return err(null, -32001, 'missing app token', 401);
      // cacheTtl: an uncached KV read at the caller's colo is a cross-region trip on EVERY call, and a flow makes
      // 10–30 sequential calls (measured 2026-10-07). See TOKEN_CACHE_TTL_S for what it costs revocation.
      const rec = await env.TOKENS.get(`t:${await sha256(bearer)}`, { type: 'json', cacheTtl: TOKEN_CACHE_TTL_S }) as { app: string; readRps: number; writeRps: number } | null;
      if (!rec) return err(null, -32001, 'unknown or revoked app token', 401);
      let body: Rpc | Rpc[]; try { body = await req.json(); } catch { return err(null, -32700, 'parse error'); }
      const calls = Array.isArray(body) ? body : [body];
      injectEstimateGasCap(calls, env.ESTIMATE_GAS_CAP);
      if (calls.length === 0 || calls.length > 50) return err(null, -32600, 'empty or oversized batch');
      for (const c of calls) if (typeof c?.method !== 'string' || !isAllowed(c.method)) return err(c?.id ?? null, -32601, `method not permitted: ${c?.method}`, 403);
      const reads = calls.filter(c => !isWrite(c.method)).length, writes = calls.length - reads;
      const take = () => {
        const rl = env.RATE.get(env.RATE.idFromName(rec.app));
        return rl.fetch('https://rl/take', { method: 'POST', body: JSON.stringify({ reads, writes, readRps: rec.readRps, writeRps: rec.writeRps }) }).then(r => r.json() as Promise<{ ok: boolean; retryAfter?: number }>);
      };
      const limited = (ok: { retryAfter?: number }) => err(calls[0]?.id ?? null, -32005, `rate limited (retry ~${ok.retryAfter}s)`, 429);
      // A cacheable single read is looked up BEFORE the rate limiter: the limiter is a Durable Object with a
      // durable write per call — a cross-region round trip on every request — and a HIT costs the origin
      // nothing, so it does not spend the app's read budget. A MISS still pays the limiter before the origin,
      // so the budget still bounds what reaches the chain. Token check, allow-list and gas cap are unchanged.
      const ttl = Array.isArray(body) ? 0 : CACHE_TTL_S(body.method, body.params ?? []);
      if (!Array.isArray(body) && ttl > 0) {
        const key = new Request(cacheKey(env.ORIGIN, body.method, await sha256(JSON.stringify(body.params ?? []))));
        const hit = await caches.default.match(key);
        if (hit) { const j = await hit.json() as { result?: unknown }; return new Response(JSON.stringify({ jsonrpc: '2.0', id: body.id, result: j.result }), { headers: { 'content-type': 'application/json', 'x-cache': 'HIT' } }); }
        const ok = await take();
        if (!ok.ok) return limited(ok);
        const res = await forward(env, body); const j = await res.clone().json() as { error?: unknown; result?: unknown };
        // Never cache an error OR a null/absent result — a pending tx's receipt/getBlock returns
        // null, and caching it would mask the real value for the whole TTL (starves receipt polls).
        if (!j.error && j.result != null) ctx.waitUntil(caches.default.put(key, new Response(await res.clone().text(), { headers: { 'cache-control': `max-age=${ttl}` } })));
        const h = new Headers(res.headers); h.set('x-cache', 'MISS'); return new Response(res.body, { status: res.status, headers: h });
      }
      const ok = await take();
      if (!ok.ok) return limited(ok);
      return forward(env, body);
    };

    const res = await run();
    const h = new Headers(res.headers);
    for (const [k, v] of Object.entries(cors)) h.set(k, v);
    return new Response(res.body, { status: res.status, headers: h });
  },
};
