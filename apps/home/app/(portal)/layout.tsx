'use client';
// The portal gate: wraps every (portal)/* route. Decides what `/` and the sections render —
// the onboarding/sign-in EntryExperience when not authed (or mid relying-app enrollment),
// the PortalShell when authed. Mirrors the old App.tsx `if (enrollReq){…}` early-return:
// an enrollment takes precedence over any stale session.
import dynamic from 'next/dynamic';
import { useEffect, useRef, useState, type ReactNode } from 'react';
import { SessionProvider, useSession } from '../../src/context/session';
import { activateVaultIfNeeded } from '../../src/home/onboarding';
import { EntryExperience } from '../../src/components/onboarding/EntryExperience';
import { GoogleSecureHome } from '../../src/components/onboarding/GoogleSecureHome';
import { GoogleEnrollResume, readPendingEnroll } from '../../src/components/onboarding/GoogleEnrollResume';
import { HomeResolvedView } from '../../src/components/onboarding/HomeResolvedView';
import { parseEnrollReq } from '../../src/components/onboarding/useEnrollReq';
import { enrollResumeHref, isConnectPopup } from '../../src/components/onboarding/pending-enroll';
import { ClientThemeScope } from '../../src/components/onboarding/ClientThemeScope';
import { whitelabel } from '../../src/whitelabel/config';
import { clientTheme } from '../../src/whitelabel/client-consent';

/** The registered look of the CURATED client `aud`, if it has one. Member-registered clients are never
 *  consulted: they cannot carry a theme (relying-clients.ts rebuilds them field by field). */
function themeFor(aud: string | undefined) {
  return aud ? clientTheme(whitelabel.relyingApps.find((a) => a.client_id === aud)) : undefined;
}

function FullBleedSpinner() {
  return (
    <div className="fullbleed-spinner" role="status" aria-label="Loading">
      <span className="spinner spinner-lg" />
    </div>
  );
}

// The SIGNED-IN portal, loaded only when somebody is signed in.
//
// This gate renders one of two branches and used to import both eagerly, so a visitor who is NOT
// signed in — every relying-app consent screen comes through here — downloaded the whole portal to
// be shown a consent sheet. PortalShell pulls HuddleProvider, and that pulls the WebRTC client:
// 624 KB of video conferencing on the sign-in path, measured off the live deployment.
//
// ssr:false costs nothing here: the gate already refuses to render authed content server-side
// (the mounted check below), and the same FullBleedSpinner covers the load, so the swap is unseen.
const PortalShell = dynamic(() => import('../../src/components/portal/PortalShell').then((m) => m.PortalShell), {
  ssr: false,
  loading: () => <FullBleedSpinner />,
});

// A relying app redirected here for enrollment/consent (spec 230) — takes precedence over
// any stale session, mirroring the old App.tsx `if (enrollReq){…}` early return.
function hasEnrollParams(): boolean {
  return !!parseEnrollReq();
}

function Gate({ children }: { children: ReactNode }) {
  const { phase, session, agentName, agentAddress, agentDeployed, notice, clearNotice, refreshProfile } = useSession();
  const [mounted, setMounted] = useState(false);
  const [enroll, setEnroll] = useState(false);
  const [pendingEnroll, setPendingEnroll] = useState(false);
  // spec 257 W3 — a one-shot "Welcome back" beat shown the first time a fresh Google sign-in
  // resolves to an EXISTING home, before the portal. Dismisses to the portal on continue; never
  // re-shows for restored sessions (only `session.fresh`).
  const [welcomedBack, setWelcomedBack] = useState(false);
  useEffect(() => {
    setEnroll(hasEnrollParams());
    setPendingEnroll(!!readPendingEnroll());
    setMounted(true);
  }, [phase]);

  // A brand-new Google home already showed its own "You're in." reward in GoogleSecureHome (which
  // sets this flag just before refreshing in) — suppress the gate's returning-member beat so it
  // doesn't double-fire once the profile gains a name. Read at render: the flag may be set after
  // mount, in the same Gate instance, when GoogleSecureHome transitions us to an authed profile.
  let bootstrapReward = false;
  try { bootstrapReward = !!sessionStorage.getItem('homeWelcomeShown'); } catch { /* ignore */ }
  // Consume it once we're past the freshness window (restored / non-fresh) so a later sign-out →
  // sign-in cycle gets a fresh "Welcome back" beat.
  useEffect(() => {
    if (bootstrapReward && (!session?.fresh || phase !== 'authed')) {
      try { sessionStorage.removeItem('homeWelcomeShown'); } catch { /* ignore */ }
    }
  }, [bootstrapReward, session?.fresh, phase]);

  // KMS-custodied OIDC homes (Google / YouVersion / email / phone — specs 235/319/320) share the
  // server-side secure-home / enroll-resume / welcome-back beats — the demo-a2a bridge derives the
  // custodian from the session (iss, sub) for all of them. Case-insensitive, whole family (the exact
  // 'Google'|'YouVersion' match excluded phone/email homes from the spec-278 vault self-heal).
  const sessionViaLc = (session?.via ?? '').toLowerCase();
  const isOidcHome = sessionViaLc === 'google' || sessionViaLc === 'youversion' || sessionViaLc === 'email' || sessionViaLc === 'phone';

  // spec 278 self-heal — a deployed-but-UNBOUND OIDC member would otherwise be stuck at
  // `vault_key_unauthorized` in relying apps (e.g. onboarded before the enroll-time bind, or after a
  // swallowed best-effort failure). The enroll/secure-home flows only bind during enroll / pre-deploy;
  // a member who is already deployed lands straight in the portal with no bind attempt. Fire the
  // IDEMPOTENT ceremony once per authed portal load (skips if already bound; zero device prompt for KMS;
  // fire-and-forget so a vault hiccup never blocks the portal). This recovers any stuck OIDC member the
  // next time they open their home, and is a no-op for already-bound members.
  const healedRef = useRef(false);
  useEffect(() => {
    if (healedRef.current) return;
    if (phase !== 'authed' || !isOidcHome || !agentDeployed || !agentAddress || !session?.token) return;
    healedRef.current = true;
    const via = sessionViaLc === 'youversion' || sessionViaLc === 'email' || sessionViaLc === 'phone' ? sessionViaLc : 'google';
    void activateVaultIfNeeded(agentAddress, via, { token: session.token }).catch(() => { /* non-fatal */ });
  }, [phase, isOidcHome, agentDeployed, agentAddress, session?.token, session?.via]);

  // Stale-header self-heal: a home that just claimed its name (any surface — OTP secure-home, the
  // claim cards) can land in the portal while the server's reverse-resolve still lags, so the topbar
  // shows the raw ADDRESS until a manual refresh. Bounded poll: re-read the profile a few times while
  // a deployed home is nameless, then nudge the workspace dropdowns. Genuinely-nameless homes just
  // spend 5 cheap reads and stop — never an infinite loop.
  const nameHealRef = useRef(false);
  useEffect(() => {
    if (nameHealRef.current) return;
    if (phase !== 'authed' || !agentDeployed || agentName || !session?.token) return;
    nameHealRef.current = true;
    void (async () => {
      for (let i = 0; i < 5; i++) {
        await new Promise((r) => setTimeout(r, 3000));
        await refreshProfile();
      }
      const { notifyAgentsChanged } = await import('../../src/components/portal/ManagedAgents');
      notifyAgentsChanged();
    })();
  }, [phase, agentDeployed, agentName, session?.token, refreshProfile]);

  // A fresh OIDC return that already has a home (no secure-home step, no enroll) → show the welcome-back
  // beat once. (Passkey/wallet/name surface their own beat in EntryExperience.)
  const showGoogleWelcomeBack =
    mounted && phase === 'authed' && isOidcHome && session?.fresh &&
    !!agentName && !enroll && !pendingEnroll && !welcomedBack && !bootstrapReward;

  const connectPopup = mounted && isConnectPopup();
  const resumedEnroll = useRef(false);

  let content: ReactNode;
  // The relying app whose sign-in window this is, when it is one — its registered look (if any) wraps
  // the screens below. Only the enrollment branches set it: the portal itself always looks like the Home.
  let windowClient: string | undefined;
  if (!mounted) content = <FullBleedSpinner />; // stable SSR/first-paint (no authed content server-side)
  else if (enroll) {
    windowClient = parseEnrollReq()?.aud;
    content = <EntryExperience mode="enroll" />;
  }
  else if (phase === 'restoring') content = <FullBleedSpinner />;
  else if (phase === 'anon') content = <EntryExperience mode="entry" />;
  // A Google member returned mid relying-app enrollment — finish securing + granting + deliver the
  // code back to the app (the enroll request was stashed before the Google redirect; spec 235).
  else if (isOidcHome && pendingEnroll && (connectPopup || session?.fresh)) {
    windowClient = readPendingEnroll()?.enroll.aud;
    content = <GoogleEnrollResume />;
  }
  // Email/passkey in the Gather popup landed on `/` after creating the home. Put authorize
  // back on the URL so RecognizedEnroll asks for Gather27 — do not dump the first-party portal.
  else if (connectPopup && pendingEnroll && phase === 'authed') {
    const pending = readPendingEnroll();
    windowClient = pending?.enroll.aud;
    if (pending && !resumedEnroll.current) {
      resumedEnroll.current = true;
      window.location.replace(enrollResumeHref(pending));
      content = <FullBleedSpinner />;
    } else content = <EntryExperience mode="enroll" />;
  }
  // A Google member returns ALREADY in a custody session but with no home DEPLOYED yet (their
  // `sub` is a counterfactual SA) — secure it before entering the portal (spec 235 P2.4). spec 257
  // Phase 1.5: gate on DEPLOYMENT, not name — a deployed-but-nameless home (true name-deferral)
  // must fall through to the portal, where it claims a public name by choice (ClaimPublicNameCard).
  else if (isOidcHome && !agentDeployed) content = <GoogleSecureHome />;
  // spec 257 W3 — "Welcome back, <handle>" beat for a returning Google member (existing home).
  else if (showGoogleWelcomeBack) {
    content = (
      <HomeResolvedView
        fresh={false}
        knownName={agentName}
        address={agentAddress}
        token={session?.token ?? null}
        onContinue={() => setWelcomedBack(true)}
      />
    );
  } else if (connectPopup && phase === 'authed') {
    content = (
      <HomeResolvedView
        fresh={!!session?.fresh}
        knownName={agentName}
        address={agentAddress}
        token={session?.token ?? null}
        appName="the app"
        onContinue={() => window.close()}
      />
    );
  } else content = <PortalShell>{children}</PortalShell>;

  return (
    <>
      {notice && (
        <div className="notice-banner" role="status" aria-live="polite">
          <span className="notice-banner-text">{notice}</span>
          <button className="notice-banner-close" onClick={clearNotice} aria-label="Dismiss">×</button>
        </div>
      )}
      <ClientThemeScope theme={themeFor(windowClient)}>{content}</ClientThemeScope>
    </>
  );
}

export default function PortalLayout({ children }: { children: ReactNode }) {
  return (
    <SessionProvider>
      <Gate>{children}</Gate>
    </SessionProvider>
  );
}
