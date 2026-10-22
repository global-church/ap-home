'use client';
// Session context for the portal shell. Holds the signed-in agent session + profile,
// restores it on load, and handles the Google OIDC `?code` return. Extracted verbatim
// from the old monolithic App.tsx (same SESSION_KEY, same fetchProfile validation) so
// every portal route shares one session via useSession().
import { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react';
import type { Address } from '@agenticprimitives/types';
import { AUD, cacheConnectionCustodian, fetchProfile, type BasicProfile } from '../connect-client';
import { loadImpactProfile } from '../profile-store';
import { provisionsAgentPlaybook } from '../whitelabel/provisioning';
import { exchangeCode } from '../server-client';
import { nameLabel, parseAgentSubdomain } from '../lib/domain';
import { setSsoCookie, readSsoCookie, clearSsoCookie } from '../lib/sso-cookie';
import { isAllowedRelyingOrigin } from '../lib/oidc-clients';

export interface Session {
  token: string;
  via: string; // 'wallet' | 'passkey' | 'Google'
  fresh: boolean; // just created (welcome) vs reconnected (welcome back)
}

export type SessionPhase = 'restoring' | 'anon' | 'authed';

interface SessionCtx {
  phase: SessionPhase;
  session: Session | null;
  profile: BasicProfile | null;
  /** The agent's address, derived from `profile.agent` (CAIP-10 tail). */
  agentAddress: Address | null;
  agentName: string | null;
  /** The person's PROFILE name ("Rich Pedersen") from their own vault profile (first + last), when they
   *  have given one — the header and the foot of the nav lead with it and fall back to the handle.
   *  Best-effort and private: read over the person's own session, never published; null when the vault
   *  key or interactions plane is not yet active (the handle carries the header until it is). */
  personName: string | null;
  /** spec 257 Phase 1.5 — is the SA deployed on-chain? Distinguishes a counterfactual fresh-Google
   *  SA (false → secure-home) from a deployed-but-nameless deferred home (true → portal). */
  agentDeployed: boolean;
  /** A Google return / link notice to surface in the UI (auto-cleared on dismiss). */
  notice: string | null;
  clearNotice(): void;
  openSession(token: string, via: string, fresh: boolean): Promise<BasicProfile | null>;
  signOut(): void;
  /** Re-read `/me/profile`; resolves to what was read (null when it could not be read). */
  refreshProfile(): Promise<BasicProfile | null>;
  /** Re-read the profile name after the person edits their profile. */
  refreshPersonName(): Promise<void>;
}

// Spec 311 — the authority deployment epoch. Mirrors @agenticprimitives/connect-client's
// checkDeploymentEpoch, inlined here because the HOME is not a relying app and must not pull the
// relying-client package into its Vercel build. A stored session's id_token `sub` carries the
// person's OLD-factory SA after a full-reset redeploy; dropping it forces a re-onboard onto the
// correct new-factory identity. `undefined` current epoch does NOT gate (only invalidate when knowable).
import { DEPLOYMENT_EPOCH } from '../lib/chain';
import { shouldRestoreFromUrl } from './session-restore';
import { ensurePlaybook } from '../home/ensure-playbook';
import { activateInteractionsIfNeeded, resolveVia } from '../home/onboarding';
function epochStale(stored: string | undefined): boolean {
  if (!DEPLOYMENT_EPOCH) return false; // unknowable → don't gate
  return stored !== DEPLOYMENT_EPOCH; // stale (differs) OR unstamped (absent) → reconnect
}

export const SESSION_KEY = 'agenticprimitives:demo-sso:session';
const Ctx = createContext<SessionCtx | null>(null);

/** Tell the browser's FedCM login-status API the user's IdP state (Chrome-only; feature-detected). With
 *  `logged-in`, FedCM will call `/fedcm/accounts`; with `logged-out` it shows the `login_url` affordance
 *  instead of erroring. Without this signal FedCM treats the IdP state as `unknown` and an accounts 401
 *  surfaces as an error (spec 264 Phase 1b). */
export function setFedcmLoginStatus(status: 'logged-in' | 'logged-out'): void {
  try {
    (navigator as unknown as { login?: { setStatus?: (s: string) => void } }).login?.setStatus?.(status);
  } catch {
    /* not supported — fine */
  }
}

function shouldRestore(): boolean {
  try {
    return shouldRestoreFromUrl(
      window.location.href,
      !!localStorage.getItem(SESSION_KEY),
      !!readSsoCookie(),
    );
  } catch {
    return false;
  }
}

function hasGoogleReturn(): boolean {
  try {
    const u = new URL(window.location.href);
    return u.searchParams.has('code') || u.searchParams.has('connect_status');
  } catch {
    return false;
  }
}

/** Relying-app `#session=` handoff (demo personas / SIWE) — treat like restore so pages that require
 *  a Home session (e.g. /enable-messaging) wait instead of flashing "Sign in first". */
export function hasSessionHandoff(): boolean {
  try {
    return !!new URLSearchParams(window.location.hash.replace(/^#/, '')).get('session');
  } catch {
    return false;
  }
}

export function SessionProvider({ children }: { children: React.ReactNode }) {
  const [session, setSession] = useState<Session | null>(null);
  const [profile, setProfile] = useState<BasicProfile | null>(null);
  const [personName, setPersonName] = useState<string | null>(null);
  // 'restoring' while we validate a stored session, finish a Google ?code exchange, or consume `#session=`.
  const [phase, setPhase] = useState<SessionPhase>(() => {
    if (typeof window === 'undefined') return 'restoring';
    return shouldRestore() || hasGoogleReturn() || hasSessionHandoff() ? 'restoring' : 'anon';
  });
  const [notice, setNotice] = useState<string | null>(null);
  const ran = useRef(false);

  const openSession = useCallback(async (token: string, via: string, fresh: boolean): Promise<BasicProfile | null> => {
    setSession({ token, via, fresh });
    try {
      localStorage.setItem(SESSION_KEY, JSON.stringify({ token, via, deploymentEpoch: DEPLOYMENT_EPOCH })); // survive refresh (this origin)
    } catch {
      /* storage blocked (private mode) — session just won't persist */
    }
    setSsoCookie(token, via); // share across *.impact-agent.me (parent-domain SSO)
    setFedcmLoginStatus('logged-in'); // FedCM may now call /fedcm/accounts (spec 264)
    const p = await fetchProfile(token);
    setProfile(p);
    setPhase('authed');
    // spec 321 W0 — a KMS/social custody session caches its C_sub (public on-chain address) so a
    // LATER passkey-session org create on this browser can mirror it onto the org. Fire-and-forget.
    if (p?.agent) {
      const addr = p.agent.split(':').pop() as Address;
      void cacheConnectionCustodian(addr, via, token);
    }
    // Remember how THIS browser last opened this home, so the welcome-back sign-in leads with the
    // same method (local convenience only — the PUBLIC pre-select stays the opt-in spec-280 record).
    try {
      if (p?.name) localStorage.setItem(`ap-last-via:${nameLabel(p.name)}`, via.toLowerCase());
    } catch { /* storage blocked */ }
    return p;
  }, []);

  const signOut = useCallback(() => {
    // Full SSO teardown is `/logout`: it clears this origin AND front-channel-notifies
    // registered relying apps (Commons keeps its own cookie). In-place clear left those
    // apps signed in.
    const here = window.location.href;
    window.location.assign(`/logout?return=${encodeURIComponent(here)}`);
  }, []);

  const refreshProfile = useCallback(async (): Promise<BasicProfile | null> => {
    if (!session) return null;
    const p = await fetchProfile(session.token, { fresh: true });
    setProfile(p);
    return p;
  }, [session]);

  // The profile name is a vault read (private tier); a home whose vault key or interactions plane is
  // not active yet simply has none — the handle leads until then. Never an error the shell surfaces.
  const addrOf = (p: BasicProfile | null) => (p?.agent ? (p.agent.split(':').pop() as Address) : null);
  const readPersonName = useCallback(async (p: BasicProfile | null) => {
    const addr = addrOf(p);
    if (!addr || !p?.deployed) { setPersonName(null); return; }
    try {
      const stored = await loadImpactProfile(addr);
      const c = stored.contact ?? {};
      const full = [c.firstName, c.lastName].map((s) => (s ?? '').trim()).filter(Boolean).join(' ');
      setPersonName(full || null);
    } catch {
      setPersonName(null);
    }
  }, []);
  const refreshPersonName = useCallback(async () => { await readPersonName(profile); }, [profile, readPersonName]);
  // Keyed on WHO the profile is (address + deployed), not on the profile object: every `refreshProfile`
  // makes a new object, and re-reading the vault record each time was eight slow reads in one publish.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => { if (phase === 'authed') void readPersonName(profile); }, [phase, profile?.agent, profile?.deployed, readPersonName]);
  // Spec 354 §3 self-heal — a deployed person agent with no playbook gets the estate's default, once per session.
  useEffect(() => {
    const addr = profile?.agent ? (profile.agent.split(':').pop() ?? '') : '';
    if (phase !== 'authed' || !session?.token || !profile?.deployed || !/^0x[0-9a-fA-F]{40}$/.test(addr)) return;
    // A relying app's sign-in window may skip this (whitelabel `provisioning.agentPlaybook: false`): it is a
    // steward-gated write the portal wants, not something a person waiting to get back to an app should pay for.
    const askedBy = typeof window === 'undefined' ? undefined : (new URL(window.location.href).searchParams.get('client_id') ?? undefined);
    if (provisionsAgentPlaybook(askedBy)) void ensurePlaybook(addr, session.token);
    // Spec 412 W5 — the interactions plane's SESSION LEAF (12 h by issue) is re-issued here when the DO reports it
    // expired: without it the agent cannot sign as the person. Once per session; silent for KMS / demo custody, one
    // prompt for a device credential; best-effort and said (the plane keeps serving reads without a live leaf).
    const via = resolveVia((profile as { credential?: string } | null)?.credential, session.via);
    void activateInteractionsIfNeeded(addr as Address, via, { token: session.token }).then((r) => { if (!r.ok) console.warn('[interactions] leaf/grant refresh skipped:', r.error); }).catch(() => undefined);
  }, [phase, session?.token, profile?.agent, profile?.deployed]);

  // On mount: handle a Google return (?code / connect_status), else restore a stored session.
  useEffect(() => {
    if (ran.current) return;
    ran.current = true;
    void (async () => {
      const url = new URL(window.location.href);

      // One-click SIWE handoff (spec 247): a relying app (e.g. demo-jp) signed the operator
      // in with their key and opened us at `…/you#session=<token>`. Establish the session
      // straight from the fragment, then strip it so the token never lingers in history.
      const hashParams = new URLSearchParams(url.hash.replace(/^#/, ''));
      const handoff = hashParams.get('session');
      if (handoff) {
        window.history.replaceState({}, '', url.pathname + url.search);
        try {
          const via = hashParams.get('via') || 'Wallet';
          await openSession(handoff, via, true);
          // An enroll (`client_id` / `delegate`) must stay here so RecognizedEnroll can
          // authorize that app as this home. Bouncing to `return` would drop the grant.
          const enrolling = url.searchParams.has('client_id') || url.searchParams.has('delegate');
          if (enrolling) {
            // Same key RecognizedEnroll uses. Without it, nameless site-login
            // force-chooses and wipes the session we just planted.
            const chooserKey = url.searchParams.get('state') || url.searchParams.get('code_challenge') || '';
            if (chooserKey) {
              try { sessionStorage.setItem(`ap_chooser:${chooserKey}`, '1'); } catch { /* blocked */ }
            }
          }
          // Bounce ONLY on a `return` the HANDOFF itself carried (in the fragment, next to the
          // session). A `?return=` search param belongs to the PAGE — ceremony pages like
          // /approve-messaging carry one so THEY can send the person back after signing, and
          // bouncing on it here unloads the ceremony before it ever runs.
          const ret = hashParams.get('return');
          if (!enrolling && ret && isAllowedRelyingOrigin(ret)) {
            window.location.replace(ret);
            return;
          }
        } catch {
          setPhase('anon');
        }
        return;
      }

      // Google bootstrap notice (the callback redirects back with a status, not a dead JSON page).
      const connectStatus = url.searchParams.get('connect_status');
      if (connectStatus) {
        const email = url.searchParams.get('email');
        const reason = url.searchParams.get('reason');
        if (connectStatus === 'linked') {
          setNotice(`✓ Google${email ? ` (${email})` : ''} is now linked — next time you can sign in with Google.`);
        } else if (connectStatus === 'link_failed') {
          setNotice(`Couldn't link Google: ${reason ?? 'please try again'}.`);
        } else {
          setNotice(
            `We recognized your Google account${email ? ` (${email})` : ''}, but no portal is linked to it yet. ` +
              `Create one with a passkey or wallet — or sign in and use "Link Google".`,
          );
        }
        for (const k of ['connect_status', 'via', 'email', 'reason']) url.searchParams.delete(k);
        window.history.replaceState({}, '', url.toString());
        setPhase('anon');
        return;
      }

      // Real OIDC return: ?code → exchange → session. `via` (default Google) names which IdP opened it —
      // both Google and YouVersion are KMS-custodied, so the credential label drives custody routing.
      const code = url.searchParams.get('code');
      if (code && !url.searchParams.has('delegate')) {
        const credVia = url.searchParams.get('via') === 'youversion' ? 'YouVersion' : 'Google';
        try {
          const token = await exchangeCode(code, AUD);
          const prof = await openSession(token, credVia, true);
          // Google is one-account-one-home: if it resolved to an EXISTING home that differs from
          // the name the member just asked for, tell them (their Google account is already bound).
          // A brand-new member (no home yet) keeps `pendingHomeName` for the secure-home step.
          if (prof?.name) {
            const pending = sessionStorage.getItem('pendingHomeName');
            const want = pending ? nameLabel(pending) : '';
            if (want && nameLabel(prof.name) !== want) {
              setNotice(
                `Your ${credVia} account already opens ${prof.name}. Signing in with ${credVia} always brings you ` +
                  `here — to set up a separate “${want}”, secure it with a passkey or wallet instead.`,
              );
            }
            try {
              sessionStorage.removeItem('pendingHomeName');
            } catch {
              /* ignore */
            }
          }
        } catch {
          setPhase('anon');
        } finally {
          url.searchParams.delete('code');
          url.searchParams.delete('state');
          url.searchParams.delete('via');
          window.history.replaceState({}, '', url.toString());
        }
        return;
      }

      // Restore a persisted session (validated against the broker; drop if expired/invalid).
      if (!shouldRestore()) {
        setPhase('anon');
        return;
      }
      try {
        // Prefer the per-origin localStorage session; else fall back to the parent-domain SSO
        // cookie (signed in once on another *.impact-agent.me origin).
        const raw = localStorage.getItem(SESSION_KEY);
        const stored = raw ? (JSON.parse(raw) as { token?: string; via?: string; deploymentEpoch?: string }) : null;
        let token = stored?.token;
        let via = stored?.via;
        let restoredEpoch = stored?.deploymentEpoch;
        let fromCookie = false;
        if (!token) {
          const c = readSsoCookie();
          if (c) {
            token = c.token;
            via = c.via;
            restoredEpoch = c.deploymentEpoch;
            fromCookie = true;
          }
        }
        if (!token || !via) {
          localStorage.removeItem(SESSION_KEY);
          setPhase('anon');
          return;
        }
        // Spec 311 — a full-reset redeploy since this session/cookie was minted means its id_token
        // references an old-factory SA (and any grant signed for it fails on the new DelegationManager).
        // Drop BOTH the localStorage session AND the cross-subdomain SSO cookie (an unstamped, pre-guard
        // cookie is treated as stale) so the user re-onboards onto the live identity.
        if (epochStale(restoredEpoch)) {
          localStorage.removeItem(SESSION_KEY);
          clearSsoCookie();
          setPhase('anon');
          return;
        }
        const p = await fetchProfile(token);
        if (!p) {
          localStorage.removeItem(SESSION_KEY);
          if (fromCookie) clearSsoCookie();
          setPhase('anon');
          return;
        }
        // A cookie session landing on a DIFFERENT home's subdomain must NOT impersonate that home
        // here — let them sign in as THIS subdomain's home (keep the cookie for its own home).
        if (fromCookie) {
          const sub = parseAgentSubdomain(window.location.hostname);
          if (sub && p.name && nameLabel(p.name) !== sub) {
            setPhase('anon');
            return;
          }
        }
        setSession({ token, via, fresh: false });
        setProfile(p);
        setPhase('authed');
        // spec 264 — a RESTORED session (returning user) must also (a) refresh the SSO cookie so an old
        // SameSite=Lax cookie is upgraded to SameSite=None (FedCM's cross-site accounts/assertion fetch
        // can't read a Lax cookie), and (b) signal `logged-in` to FedCM. Without this, a logged-in user
        // is invisible to FedCM and it shows the sign-in screen instead of the account chooser.
        setSsoCookie(token, via);
        setFedcmLoginStatus('logged-in');
        // spec 321 W0 — restored custody sessions also cache their C_sub (see openSession).
        if (p.agent) void cacheConnectionCustodian(p.agent.split(':').pop() as Address, via, token);
        if (fromCookie) {
          try {
            localStorage.setItem(SESSION_KEY, JSON.stringify({ token, via })); // cache on this origin
          } catch {
            /* ignore */
          }
        }
      } catch {
        setPhase('anon');
      }
    })();
  }, [openSession]);

  const agentAddress = (profile?.agent ? (profile.agent.split(':').pop() as Address) : null) ?? null;
  const agentName = profile?.name ?? null;
  const agentDeployed = profile?.deployed ?? false;

  const value: SessionCtx = {
    phase,
    session,
    profile,
    agentAddress,
    agentName,
    agentDeployed,
    notice,
    clearNotice: () => setNotice(null),
    openSession,
    signOut,
    refreshProfile,
    personName,
    refreshPersonName,
  };
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useSession(): SessionCtx {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error('useSession must be used within <SessionProvider>');
  return ctx;
}
