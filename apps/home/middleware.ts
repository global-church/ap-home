// The pre-launch password (src/lib/site-gate.ts). Off unless HOME_SITE_PASSWORD is set; every rule about what
// it must never stand in front of lives there, next to its tests.
//
// While it is on, nothing is indexed either (Global.Church, 2026-10-09): every response carries
// `X-Robots-Tag: noindex, nofollow` and /robots.txt disallows everything. Removing the password at go-live
// lifts both — there is no second switch to forget.
import { NextResponse, type NextRequest } from 'next/server';

import { decide, gatePageHtml } from './src/lib/site-gate';

const NOINDEX = 'noindex, nofollow';

function closed(res: NextResponse): NextResponse {
  res.headers.set('X-Robots-Tag', NOINDEX);
  return res;
}

export async function middleware(req: NextRequest) {
  const password = process.env.HOME_SITE_PASSWORD;
  if (!password) return NextResponse.next();
  if (req.nextUrl.pathname === '/robots.txt') {
    return closed(new NextResponse('User-agent: *\nDisallow: /\n', { headers: { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' } }));
  }
  const decision = await decide({
    password,
    cookieDomain: process.env.HOME_GATE_COOKIE_DOMAIN,
    method: req.method,
    url: req.nextUrl,
    headers: req.headers,
    cookies: (name) => req.cookies.get(name)?.value,
    form: async () => {
      const f = await req.formData().catch(() => null);
      return { p: String(f?.get('p') ?? ''), next: String(f?.get('next') ?? '/') };
    },
  });
  switch (decision.kind) {
    case 'pass':
      return closed(NextResponse.next());
    case 'pass-flow': {
      const res = NextResponse.next();
      res.headers.append('set-cookie', decision.setCookie);
      return closed(res);
    }
    case 'redirect': {
      // NextResponse requires an absolute Location ("Invalid URL" on a relative one — found live 2026-10-07).
      // decision.location is already a same-origin relative path (safeNext), so resolve it against this origin.
      const res = NextResponse.redirect(new URL(decision.location, req.nextUrl.origin), 303);
      res.headers.append('set-cookie', decision.setCookie);
      return closed(res);
    }
    case 'page':
      return closed(new NextResponse(gatePageHtml(process.env.NEXT_PUBLIC_BRAND_NAME ?? 'Home', decision.wrong, decision.next), {
        status: 401,
        headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' },
      }));
  }
}

// Static build output never reaches the middleware at all; everything else is decided by site-gate.ts.
export const config = {
  matcher: ['/((?!_next/static|_next/image).*)'],
};
