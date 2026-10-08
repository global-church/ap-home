/**
 * The pre-launch password for a Home (Global.Church, 2026-10-07): until launch, a person who browses to the
 * Home sees a password page. Off unless `HOME_SITE_PASSWORD` is set, so every other deployment of this Home
 * behaves exactly as before.
 *
 * What it must NEVER stand in front of, because a password page there breaks sign-in for every relying app:
 *  - anything that is not a browser page navigation — fetches, server-to-server calls, the Workers. Only a
 *    request with `Sec-Fetch-Mode: navigate` (or, from an older client, `Accept: text/html`) is gated;
 *  - the machine paths, listed below, even when a browser navigates to one (a JWKS link, a logout hop);
 *  - the sign-in window a relying app opens. Its authorization endpoint is `/` (server/.well-known/
 *    openid-configuration.ts), so a navigation to `/` carrying `client_id` and `redirect_uri` passes, and gets
 *    a short `home_flow` cookie so the window's later steps (email code, consent, org setup) pass too. That
 *    request is still checked against the client registry by the page itself, so the pass opens a sign-in
 *    form and nothing else — a relying app's hosts then only ever type that app's own password.
 *
 * Pure: the middleware hands it what it needs and applies the decision.
 */

export const GATE_PATH = '/__gate';
export const FLOW_COOKIE = 'home_flow';
const FLOW_MAX_AGE_S = 30 * 60;
const GATE_MAX_AGE_S = 30 * 24 * 60 * 60;

/** Machine and static paths: never a password page. Prefix match on whole segments. */
const OPEN_PREFIXES = [
  '/_next', '/api', '/connect', '/oidc', '/token', '/jwks', '/.well-known', '/a2a', '/mcp-bind', '/logout',
  '/fedcm', '/me', '/favicon', '/icon', '/apple-icon', '/opengraph-image', '/twitter-image', '/robots.txt',
  '/sitemap.xml', '/llms.txt', '/manifest',
];

export function isOpenPath(path: string): boolean {
  return OPEN_PREFIXES.some((p) => path === p || path.startsWith(`${p}/`) || (p.includes('.') && path.startsWith(p)) || path.startsWith(`${p}.`));
}

export function isPageNavigation(headers: Headers): boolean {
  const mode = headers.get('sec-fetch-mode');
  if (mode) return mode === 'navigate';
  return (headers.get('accept') ?? '').includes('text/html');
}

export function isAuthorizeRequest(path: string, search: URLSearchParams): boolean {
  return path === '/' && search.has('client_id') && search.has('redirect_uri');
}

/** Only a same-origin relative path; `//host`, `/\host` and absolute URLs are other origins. */
export function safeNext(raw: string): string {
  if (!raw.startsWith('/') || raw.startsWith('//') || raw.startsWith('/\\')) return '/';
  return raw;
}

export async function sha256Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** Per password, so two Homes sharing a parent domain cannot overwrite each other's entry. */
export const gateCookieName = (expected: string) => `home_gate_${expected.slice(0, 8)}`;

export function cookieAttrs(host: string, parentDomain: string | undefined, maxAge: number): string {
  const parent = (parentDomain ?? '').trim().toLowerCase();
  const h = host.toLowerCase();
  const domain = parent && (h === parent || h.endsWith(`.${parent}`)) ? `; Domain=${parent}` : '';
  return `Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}${domain}`;
}

export type GateDecision =
  | { kind: 'pass' }
  | { kind: 'pass-flow'; setCookie: string }
  | { kind: 'page'; wrong: boolean; next: string }
  | { kind: 'redirect'; location: string; setCookie: string };

export interface GateInput {
  readonly password: string | undefined;
  readonly cookieDomain?: string;
  readonly method: string;
  readonly url: URL;
  readonly headers: Headers;
  readonly cookies: (name: string) => string | undefined;
  /** Only read for a POST to GATE_PATH. */
  readonly form?: () => Promise<{ p: string; next: string }>;
}

export async function decide(input: GateInput): Promise<GateDecision> {
  const { password, url } = input;
  if (!password) return { kind: 'pass' };
  const path = url.pathname;
  const expected = await sha256Hex(password);

  if (input.method === 'POST' && path === GATE_PATH && input.form) {
    const { p, next } = await input.form();
    const to = safeNext(next);
    if (p && (await sha256Hex(p)) === expected) {
      return { kind: 'redirect', location: to, setCookie: `${gateCookieName(expected)}=${expected}; ${cookieAttrs(url.hostname, input.cookieDomain, GATE_MAX_AGE_S)}` };
    }
    return { kind: 'page', wrong: true, next: to };
  }

  if (isOpenPath(path) || !isPageNavigation(input.headers)) return { kind: 'pass' };
  if (input.cookies(gateCookieName(expected)) === expected) return { kind: 'pass' };

  const flowValue = (await sha256Hex(`flow:${expected}`)).slice(0, 32);
  if (isAuthorizeRequest(path, url.searchParams)) {
    return { kind: 'pass-flow', setCookie: `${FLOW_COOKIE}=${flowValue}; ${cookieAttrs(url.hostname, undefined, FLOW_MAX_AGE_S)}` };
  }
  if (input.cookies(FLOW_COOKIE) === flowValue) return { kind: 'pass' };

  return { kind: 'page', wrong: false, next: safeNext(`${path}${url.search}`) };
}

const escapeAttr = (s: string) => s.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;');

export function gatePageHtml(brand: string, wrong: boolean, next: string): string {
  const name = escapeAttr(brand || 'Home');
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>${name}</title>
<style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f7f7f5;color:#1f2328;font:16px/1.5 system-ui,sans-serif}form{background:#fff;border:1px solid #e3e3df;border-radius:10px;padding:26px 28px;max-width:360px;display:grid;gap:12px}h1{margin:0;font-size:20px}input{padding:10px 12px;border:1px solid #d6d6d0;border-radius:6px;font:inherit}button{padding:10px 16px;border:0;border-radius:6px;background:#d97706;color:#fff;font-weight:700;cursor:pointer}p{margin:0;color:#5f6368;font-size:14px}.bad{color:#b42318}</style></head>
<body><form method="post" action="${GATE_PATH}"><h1>${name}</h1><p>${name} isn’t open to the public yet. Enter the password you were given.</p>${wrong ? '<p class="bad">That wasn’t it.</p>' : ''}<input type="hidden" name="next" value="${escapeAttr(next)}"><input type="password" name="p" autofocus autocomplete="current-password" aria-label="Password"><button type="submit">Continue</button></form></body></html>`;
}
