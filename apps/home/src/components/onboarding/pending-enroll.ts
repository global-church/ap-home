// The relying-app authorize request must survive Google/email hops that strip the query
// (callback is `/`, and a www↔apex bounce is a different origin so sessionStorage dies).
// sessionStorage covers the same-origin return; a short parent-domain cookie covers the hop.
// This is not authority — PKCE verifier stays on the app; these fields are what was already in the URL.
import { CONNECT_DOMAIN } from '../../lib/domain';
import { orgTypeParam } from '../../lib/org-type';
import type { EnrollReq } from './useEnrollReq';

export const PENDING_ENROLL_KEY = 'pendingEnroll';
const COOKIE = 'ap_pending_enroll';
const MAX_AGE_SEC = 20 * 60;

export interface PendingEnroll {
  enroll: EnrollReq;
  popupMode: boolean;
  name: string;
}

function valid(p: PendingEnroll | null): PendingEnroll | null {
  if (!p?.enroll?.aud || !p.enroll.redirectUri || !p.enroll.delegate || !p.enroll.codeChallenge || !p.enroll.template) {
    return null;
  }
  return p;
}

function parse(raw: string | null): PendingEnroll | null {
  if (!raw) return null;
  try {
    return valid(JSON.parse(raw) as PendingEnroll);
  } catch {
    return null;
  }
}

function onImpactHost(): boolean {
  try {
    const h = window.location.hostname.toLowerCase();
    return h === CONNECT_DOMAIN || h.endsWith(`.${CONNECT_DOMAIN}`);
  } catch {
    return false;
  }
}

function writeCookie(raw: string): void {
  if (!onImpactHost()) return;
  try {
    document.cookie = `${COOKIE}=${encodeURIComponent(raw)}; Domain=.${CONNECT_DOMAIN}; Path=/; Max-Age=${MAX_AGE_SEC}; Secure; SameSite=Lax`;
  } catch {
    /* ignore */
  }
}

function readCookie(): string | null {
  try {
    const m = document.cookie.match(new RegExp(`(?:^|; )${COOKIE}=([^;]*)`));
    return m?.[1] ? decodeURIComponent(m[1]) : null;
  } catch {
    return null;
  }
}

function clearCookie(): void {
  if (!onImpactHost()) return;
  try {
    document.cookie = `${COOKIE}=; Domain=.${CONNECT_DOMAIN}; Path=/; Max-Age=0; Secure; SameSite=Lax`;
  } catch {
    /* ignore */
  }
}

export function writePendingEnroll(pending: PendingEnroll): void {
  const ok = valid(pending);
  if (!ok) return;
  const raw = JSON.stringify(ok);
  try {
    sessionStorage.setItem(PENDING_ENROLL_KEY, raw);
  } catch {
    /* ignore */
  }
  writeCookie(raw);
}

export function writePendingEnrollJson(json: string | undefined): void {
  if (!json) {
    clearPendingEnroll();
    return;
  }
  const p = parse(json);
  if (p) writePendingEnroll(p);
  else clearPendingEnroll();
}

export function readPendingEnroll(): PendingEnroll | null {
  try {
    const fromSession = parse(sessionStorage.getItem(PENDING_ENROLL_KEY));
    if (fromSession) return fromSession;
  } catch {
    /* ignore */
  }
  const fromCookie = parse(readCookie());
  if (fromCookie) {
    try {
      sessionStorage.setItem(PENDING_ENROLL_KEY, JSON.stringify(fromCookie));
    } catch {
      /* ignore */
    }
    return fromCookie;
  }
  return null;
}

export function clearPendingEnroll(): void {
  try {
    sessionStorage.removeItem(PENDING_ENROLL_KEY);
  } catch {
    /* ignore */
  }
  clearCookie();
}

/** True when this window is the Home popup Gather (and the other apps) opened. */
export function isConnectPopup(): boolean {
  try {
    return window.name === 'agentic-connect' || new URL(window.location.href).searchParams.get('mode') === 'popup';
  } catch {
    return false;
  }
}

export function enrollReqToQuery(e: EnrollReq): string {
  const p = new URLSearchParams();
  p.set('client_id', e.aud);
  p.set('redirect_uri', e.redirectUri);
  p.set('delegate', e.delegate);
  p.set('code_challenge', e.codeChallenge);
  p.set('delegation_template', e.template);
  p.set('agent_name', e.name ?? '');
  if (e.state) p.set('state', e.state);
  if (e.nonce) p.set('nonce', e.nonce);
  if (e.orgBase) p.set('org_base', e.orgBase);
  if (e.purpose) p.set('org_purpose', e.purpose);
  if (e.orgType) p.set('org_type', orgTypeParam(e.orgType));
  if (e.orgDisplayName) p.set('org_name', e.orgDisplayName);
  if (e.existingOrg) p.set('existing_org', e.existingOrg);
  if (e.grantOrg) p.set('grant_org', e.grantOrg);
  if (e.roleOfferRaw) p.set('role_offer', e.roleOfferRaw);
  if (e.collectToken) p.set('collect_token', e.collectToken);
  if (e.contentSignerTarget) p.set('content_signer_target', e.contentSignerTarget);
  return p.toString();
}

/** Put the authorize request back on `/` so EntryExperience / RecognizedEnroll can finish. */
export function enrollResumeHref(pending: PendingEnroll): string {
  const q = enrollReqToQuery(pending.enroll);
  return pending.popupMode ? `/?${q}&mode=popup` : `/?${q}`;
}
