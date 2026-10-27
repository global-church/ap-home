// Remote EIP-1193 signer. When the Home is opened with `?signer=remote&opener=<origin>` by an ALLOWLISTED
// origin (the uupg tracker), the wallet ceremony's signing is delegated to that opener window over
// postMessage — the opener holds the demo persona's key and signs the SIWE message + deploy userOpHash.
// The Home runs its real connect ceremony unchanged (see wallet.ts `provider()`), so it ends up with a
// genuine session for that persona's home. DEMO affordance: the key never enters this app; every action is
// still custody-authorized by the signature the opener returns. Ported from the GC impact home.

// Origins permitted to drive a remote-signer connect (relying apps whose demo personas sign
// server-side: the uupg tracker, the New City portal, and the hotspot tracker — prod + local dev).
// Must be an exact origin match — the opener param is validated against this list before we ever
// post to it.
// `NEXT_PUBLIC_REMOTE_SIGNER_OPENERS`: a comma list replaces these, and `off` turns the demo off (2026-10-27: a deployment that
// is its own estate does not let another estate's sites drive its wallet ceremony).
const OPENERS_ENV = (process.env.NEXT_PUBLIC_REMOTE_SIGNER_OPENERS ?? '').trim();
const DEFAULT_OPENER_ORIGINS = [
  'https://uupg.richardpedersen3.workers.dev',
  'http://127.0.0.1:8797',
  'http://localhost:8797',
  'https://newcity-portal.richardpedersen3.workers.dev',
  'http://127.0.0.1:8798',
  'http://localhost:8798',
  'https://hotspot-tracker.richardpedersen3.workers.dev',
  'http://127.0.0.1:8799',
  'http://localhost:8799',
];
const ALLOWED_OPENER_ORIGINS: readonly string[] =
  OPENERS_ENV.toLowerCase() === 'off' ? [] : OPENERS_ENV ? OPENERS_ENV.split(',').map((o) => o.trim()).filter(Boolean) : DEFAULT_OPENER_ORIGINS;

interface Eip1193Request {
  method: string;
  params?: unknown[];
}

const RS_MARKER = 'ap:remote-signer';
let expectedOrigin: string | null = null;
let seq = 0;

/** True if THIS tab established a remote-persona (tracker) session — even after a full reload that lost the
 *  live bridge. Lets wallet.ts block the injected-wallet fallback (which would pop MetaMask and sign as the
 *  wrong identity) and instead tell the user to return to the tracker. */
export function isRemotePersonaSession(): boolean {
  if (expectedOrigin) return true;
  try { return !!sessionStorage.getItem(RS_MARKER); } catch { return false; }
}
/** Clear the marker on a real disconnect/sign-out so a later real-wallet login isn't blocked. */
export function clearRemotePersonaMarker(): void {
  try { sessionStorage.removeItem(RS_MARKER); } catch { /* ignore */ }
}
const pending = new Map<number, { resolve: (v: unknown) => void; reject: (e: Error) => void }>();
let listenerBound = false;

/** True when the bridge is armed for this page load. Self-arms on first call (lazy) so ANY wallet touch —
 *  even one that races ahead of EntryExperience's effect — is routed to the remote signer, never the real
 *  injected wallet (MetaMask). Cheap when not in remote mode (a URL read that leaves expectedOrigin null). */
export function remoteSignerActive(): boolean {
  if (expectedOrigin === null) initRemoteSigner();
  return expectedOrigin !== null;
}

/** Arm the bridge if this page was opened in remote-signer mode by an allowlisted opener. Returns whether
 *  it armed — callers use that to auto-start the wallet connect. Safe to call repeatedly (idempotent). */
export function initRemoteSigner(): boolean {
  if (typeof window === 'undefined') return false;
  if (expectedOrigin) return true;
  let params: URLSearchParams;
  try { params = new URLSearchParams(window.location.search); } catch { return false; }
  if (params.get('signer') !== 'remote') return false;
  const opener = params.get('opener') || '';
  if (!ALLOWED_OPENER_ORIGINS.includes(opener) || !window.opener) return false;
  expectedOrigin = opener;
  // Mark this tab as a remote-persona (tracker) session. Survives full reloads in the SAME tab, so
  // wallet.ts can refuse to fall back to the injected wallet after a reload severs the postMessage bridge.
  try { sessionStorage.setItem(RS_MARKER, opener); } catch { /* storage blocked — best effort */ }
  if (!listenerBound) {
    listenerBound = true;
    window.addEventListener('message', (e: MessageEvent) => {
      if (e.origin !== expectedOrigin) return;
      const d = e.data as { __rsResp?: boolean; id?: number; result?: unknown; error?: string };
      if (!d || !d.__rsResp || typeof d.id !== 'number') return;
      const p = pending.get(d.id);
      if (!p) return;
      pending.delete(d.id);
      if (d.error) p.reject(new Error(d.error));
      else p.resolve(d.result);
    });
  }
  return true;
}

/** EIP-1193-shaped provider that fulfils each request from the opener window. Only `request` is used by
 *  wallet.ts; unsupported subscriptions are absent by design. */
export const remoteSigner = {
  request({ method, params }: Eip1193Request): Promise<unknown> {
    return new Promise((resolve, reject) => {
      if (!expectedOrigin || !window.opener) { reject(new Error('remote signer not active')); return; }
      const id = ++seq;
      pending.set(id, { resolve, reject });
      window.opener.postMessage({ __rsReq: true, id, method, params: params ?? [] }, expectedOrigin);
      // The opener signs server-side (a fetch round-trip); give it generous headroom before giving up.
      setTimeout(() => {
        if (pending.has(id)) { pending.delete(id); reject(new Error('remote signer timed out — the tracker tab must stay open')); }
      }, 90_000);
    });
  },
};
