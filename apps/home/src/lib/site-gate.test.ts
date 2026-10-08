import { describe, expect, it } from 'vitest';

import { decide, gateCookieName, isOpenPath, safeNext, sha256Hex, type GateInput } from './site-gate';

const nav = new Headers({ 'sec-fetch-mode': 'navigate', accept: 'text/html' });
const fetchHdrs = new Headers({ 'sec-fetch-mode': 'cors', accept: 'application/json' });

function input(u: string, over: Partial<GateInput> = {}, jar: Record<string, string> = {}): GateInput {
  return {
    password: 'open sesame',
    cookieDomain: 'gcid.me',
    method: 'GET',
    url: new URL(u),
    headers: nav,
    cookies: (n) => jar[n],
    ...over,
  };
}

describe('Home pre-launch password', () => {
  it('is off unless HOME_SITE_PASSWORD is set', async () => {
    expect((await decide(input('https://www.gcid.me/', { password: undefined }))).kind).toBe('pass');
  });

  it('gates a browser navigation to the home page and the portal', async () => {
    expect((await decide(input('https://www.gcid.me/'))).kind).toBe('page');
    expect((await decide(input('https://www.gcid.me/agents'))).kind).toBe('page');
  });

  it('never gates a fetch, a server call or a Worker', async () => {
    expect((await decide(input('https://www.gcid.me/agents', { headers: fetchHdrs }))).kind).toBe('pass');
    expect((await decide(input('https://www.gcid.me/', { headers: new Headers() }))).kind).toBe('pass');
  });

  it('never gates the machine paths, even on a navigation', async () => {
    for (const p of ['/jwks', '/.well-known/openid-configuration', '/oidc/token', '/token', '/a2a/rpc', '/mcp-bind/x', '/connect/related-orgs', '/logout', '/api/x', '/robots.txt', '/favicon.ico']) {
      expect(isOpenPath(p), p).toBe(true);
      expect((await decide(input(`https://www.gcid.me${p}`))).kind, p).toBe('pass');
    }
    expect(isOpenPath('/agents')).toBe(false);
    expect(isOpenPath('/meetings')).toBe(false);
  });

  it("lets a relying app's sign-in window through and remembers it for the window's next steps", async () => {
    const d = await decide(input('https://www.gcid.me/?client_id=gather-app&redirect_uri=https%3A%2F%2Fgather27.gccommons.app%2F&state=x'));
    expect(d.kind).toBe('pass-flow');
    const cookie = d.kind === 'pass-flow' ? d.setCookie : '';
    expect(cookie).toMatch(/^home_flow=[0-9a-f]{32};/);
    expect(cookie).not.toContain('Domain=');
    const value = cookie.split(';')[0]!.split('=')[1]!;
    expect((await decide(input('https://www.gcid.me/vault-key', {}, { home_flow: value }))).kind).toBe('pass');
    expect((await decide(input('https://www.gcid.me/vault-key', {}, { home_flow: 'forged' }))).kind).toBe('page');
  });

  it('a client_id alone is not a sign-in request', async () => {
    expect((await decide(input('https://www.gcid.me/?client_id=gather-app'))).kind).toBe('page');
  });

  it('the right password returns to the page asked for, on the parent domain, for 30 days', async () => {
    const d = await decide(input('https://www.gcid.me/__gate', { method: 'POST', form: async () => ({ p: 'open sesame', next: '/agents?tab=x' }) }));
    expect(d.kind).toBe('redirect');
    if (d.kind !== 'redirect') return;
    expect(d.location).toBe('/agents?tab=x');
    expect(d.setCookie).toContain('Domain=gcid.me');
    expect(d.setCookie).toContain(`Max-Age=${30 * 24 * 60 * 60}`);
    const expected = await sha256Hex('open sesame');
    expect((await decide(input('https://www.gcid.me/agents', {}, { [gateCookieName(expected)]: expected }))).kind).toBe('pass');
  });

  it('a wrong password shows the page again; an off-site next is refused', async () => {
    const d = await decide(input('https://www.gcid.me/__gate', { method: 'POST', form: async () => ({ p: 'nope', next: '//evil.example' }) }));
    expect(d).toEqual({ kind: 'page', wrong: true, next: '/' });
    expect(safeNext('https://evil.example')).toBe('/');
    expect(safeNext('/\\evil')).toBe('/');
  });

  it('a host outside the cookie domain gets a host-only cookie (staging.gcid.ai)', async () => {
    const d = await decide(input('https://staging.gcid.ai/__gate', { method: 'POST', form: async () => ({ p: 'open sesame', next: '/' }) }));
    expect(d.kind === 'redirect' && d.setCookie).not.toContain('Domain=');
  });
});
