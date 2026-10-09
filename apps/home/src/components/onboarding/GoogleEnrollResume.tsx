'use client';
import { WorkingBar } from './WorkingBar';
// Resume a relying-app enrollment AFTER a Google redirect (spec 235 + spec 230). The Google OAuth
// is a full-page redirect, so the enroll request can't survive in the URL — OnboardingJourney
// stashed it in sessionStorage before redirecting. On return the member is in a custody-grade
// Google session; here we (1) secure their home if it's brand new (server-signed, no gesture),
// (2) take the app-permission consent, (3) sign the delegation with the Google custodian, and
// (4) deliver the authorization code back to the relying app — popup postMessage or redirect,
// exactly as the in-page flow would. This is what lets "Continue with Google" return to demo-org.
import { useEffect, useRef, useState } from 'react';
import { secureHome, secureHomeNoName, givePermission, activateVaultIfNeeded, publishSocialConnectionKindIfNeeded } from '../../home/onboarding';
import { whitelabel, fmt, isPaymentTemplate } from '../../whitelabel/config';
import { useSession } from '../../context/session';
import { nameLabel } from '../../lib/domain';
import { homeLabel, type Home } from '../../home/types';
import { recordConnectedApp } from '../../lib/connected-apps';
import { clearStandingGrant } from '../../lib/grant-cache';
import { setSsoCookie } from '../../lib/sso-cookie';
import { setFedcmLoginStatus } from '../../context/session';
import { beginEnrollmentGrant, hostOf, submitEnrollGrant, deliverEnrollCode, isCeremonyTemplate } from './useEnrollReq';
import { signHashFor } from '../../home/onboarding';
import { issueAskAsMeDelegation, toWire } from '../../lib/delegation';
import { issueAppReadGrantIfDeclared } from '../../home/app-read-grant';
import { listManagedAgents, resolveTreasuryByConvention } from '../../connect-client';
import { BrandShield } from '../shared/BrandShield';
import { ReceiptCard } from '../shared/ReceiptCard';
import { ConsentSheet } from '../shared/ConsentSheet';
import { RequiredNameGate } from './RequiredNameGate';
import { NewMemberSetup } from './NewMemberSetup';
import { coinMandateLeg, grantsCoinAtConnect, newMemberPlan, planIsEmpty, withCurrencyConsent, withEmailClaimConsent, withProfileNameConsent } from '../../lib/new-member';
import { displayAppDomain, displayAppName } from './org-chooser-label';
import { hidesIdentifiers, signedInLabel, withClientConsent } from '../../whitelabel/client-consent';
import { verifiedEmailFor } from '../../lib/verified-email';
import {
  clearPendingEnroll,
  enrollResumeHref,
  readPendingEnroll,
  type PendingEnroll,
} from './pending-enroll';

export { readPendingEnroll } from './pending-enroll';

// 'new-member' — first-connect provisioning the relying app declared (`new_member`). Only a
// BRAND-NEW home passes through it; a returning Google member goes straight to consent.
type Phase = 'securing' | 'mismatch' | 'name' | 'new-member' | 'consent' | 'granting' | 'connected' | 'error';

export function GoogleEnrollResume() {
  const { session, agentAddress, agentName, agentDeployed } = useSession();
  const c = whitelabel.copy;
  const community = whitelabel.brand.community;
  const ran = useRef(false);
  const [pending] = useState<PendingEnroll | null>(() => readPendingEnroll());
  const [phase, setPhase] = useState<Phase>('securing');
  const [home, setHome] = useState<Home | null>(null);
  const [error, setError] = useState('');

  const enroll = pending?.enroll;
  const relyingApp = enroll ? whitelabel.relyingApps.find((a) => a.client_id === enroll.aud) : undefined;
  const appHost = enroll ? hostOf(enroll.redirectUri) : '';
  const appName = displayAppName(relyingApp?.name, appHost);
  const appDomain = displayAppDomain(appHost);
  const requiresNamedAgent = !!(enroll?.requireNamedAgent || relyingApp?.requireNamedAgent);
  const token = session?.token ?? '';
  // What this app declared its new members need. Empty for every app that declared nothing, which
  // makes `afterHome()` return 'consent' and this whole path identical to what it was.
  const plan = newMemberPlan(relyingApp);
  // Did THIS resume deploy the home, or find one already on chain? Only the former is a sign-up —
  // a returning nameless Google member must not be walked through account-creation setup again.
  const freshHome = useRef(false);
  const afterHome = (): Phase => (freshHome.current && !planIsEmpty(plan) ? 'new-member' : 'consent');

  const fail = (e: unknown) => {
    setError(e instanceof Error ? e.message : typeof e === 'string' ? e : 'Something went wrong');
    setPhase('error');
  };
  const clearStash = () => clearPendingEnroll();

  // Secure the home if it's brand new (Google custody → no gesture), else use the existing one.
  useEffect(() => {
    if (ran.current || !pending || !token) return;
    ran.current = true;
    void (async () => {
      // OWNER-OP (content-signer / subscription-collect) resumed via Google: the standard grant below is
      // WRONG for these (it would deliver a bare ?code). The Google sign-in just established a home
      // session — persist it cross-subdomain and RE-ENTER the enroll, so the recognized ceremony runs on
      // this session (Step 3, uniform with wallet/passkey). Fail-closed: never fall through to a grant.
      //
      // ORG-CREATE takes the same re-entry: this resume used to run the bare site-login pipeline and
      // deliver a code with NO org, so the relying app errored "no organization returned from your
      // home". The recognized ceremony owns org selection/creation (chooser, deploy, person grant).
      // A brand-new member's SA is deployed first so re-entry recognizes them.
      if (enroll && (isCeremonyTemplate(enroll.template) || enroll.template === 'org-create')) {
        if (enroll.template === 'org-create' && !(agentDeployed && agentAddress)) {
          const res = await secureHomeNoName({ token });
          if (!res.ok) return fail(res.error);
        }
        setSsoCookie(token, 'Google');
        setFedcmLoginStatus('logged-in');
        clearStash();
        // Preserve popup mode: the relying app opened a popup and expects the relay delivery.
        window.location.href = enrollResumeHref(pending);
        return;
      }
      // spec 257 §11: gate on DEPLOYMENT, not name — a RETURNING NAMELESS member has a deployed
      // SA but `agentName === null`, and must take the existing-home branch (NOT re-run secure-home
      // on an already-deployed SA). A brand-new member (no SA on-chain yet) is deployed below.
      if (agentDeployed && agentAddress) {
        // Existing Google home. If it differs from the name the app asked to connect as, STOP and
        // explain (one Google account = one home) before granting — don't silently connect the
        // wrong home. A nameless home has `agentName === null` → empty name; the mismatch check
        // below self-skips when EITHER side is empty (only meaningful when both have a name).
        setHome({ address: agentAddress, name: agentName ?? '' });
        const requested = nameLabel(pending.enroll.name);
        if (requested && nameLabel(agentName ?? '') !== requested) setPhase('mismatch');
        else if (requiresNamedAgent && !agentName) setPhase('name');
        else setPhase('consent');
        return;
      }
      // Brand-new member: TRUE name-deferral (Google only). Deploy a NAMELESS SA (empty callData,
      // subregistry slot left free) — the member claims a public handle LATER in their portal. The
      // enroll's `pending.name` ('' on the name-deferred path) is NOT consumed here.
      const res = await secureHomeNoName({ token });
      if (!res.ok) return fail(res.error);
      freshHome.current = true; // this resume created the account — the sign-up case
      setHome(res.home);
      setPhase(requiresNamedAgent ? 'name' : afterHome());
    })();
  }, [pending, token, agentName, agentAddress, requiresNamedAgent]);

  async function onAuthorize() {
    if (!enroll || !home) return;
    setPhase('granting');
    try {
      // SEC-001: server-mint the enrollment grant FIRST; use the registry-derived delegate.
      const { grant_id, delegate } = await beginEnrollmentGrant(enroll, home.name);
      // Spec 397 / 412 W5 — `ask-as-me` on the Google return: the SAME wire RecognizedEnroll mints — person → the app's
      // asking key, pinned to harness.ask, time-boxed, signed by the member's Google custodian (KMS) — and NOT the site
      // grant. This path minted a site-login delegation for every template (found live 2026-09-21: a Google-custodied
      // publisher's "wire" carried timestamp + value + allowedTargets and no allowedMethods, so her agent refused every
      // ask and the site could never publish for her).
      if (enroll.template === 'ask-as-me') {
        const signHash = await signHashFor('google', home.address, { token });
        const wire = await issueAskAsMeDelegation(home.address, delegate, signHash);
        await issueAppReadGrantIfDeclared(enroll.aud, home.address, signHash); // spec 412 W6 — best-effort, said
        const askCode = await submitEnrollGrant(grant_id, toWire(wire));
        setSsoCookie(token, 'Google');
        setFedcmLoginStatus('logged-in');
        const askTpl = whitelabel.delegationTemplates[enroll.template];
        recordConnectedApp(home.address, { clientId: enroll.aud, appName, appDomain: appHost, logo: relyingApp?.logo, canDo: askTpl?.canDo ?? [], cannotDo: askTpl?.cannotDo ?? [], grantedAt: Date.now(), expiresAt: askTpl?.expiryDays ? Date.now() + askTpl.expiryDays * 86_400_000 : undefined });
        setPhase('connected');
        clearStash();
        setTimeout(() => deliverEnrollCode(enroll, pending!.popupMode, askCode), 400);
        return;
      }
      // spec 272/243 — x402-pay: this OAuth-return path is the TERMINAL leg for every social re-auth
      // (the nameless-connect forced chooser routes here), so it MUST run the payment leg too — it
      // previously connected site-login-only, silently skipping the charge (2026-07-17). Resolve the
      // member's person-treasury (projection first, then the authoritative naming registry) and
      // authorize + charge in the same ceremony, exactly like RecognizedEnroll.
      let payment: Parameters<typeof givePermission>[5];
      let treasuryAddr: `0x${string}` | null = null;
      const pc = relyingApp?.paymentConfig;
      // The account is resolved for BOTH reasons an app can need one: a payment-template ceremony,
      // and an app whose declared currency wants its spend mandate minted in this plain sign-in.
      if ((isPaymentTemplate(enroll.template) || grantsCoinAtConnect(relyingApp)) && pc) {
        try {
          treasuryAddr = ((await listManagedAgents(token)).find((a) => a.kind === 'person-treasury')?.agent as `0x${string}`) ?? null;
        } catch (e) { console.warn('[google-resume] listManagedAgents failed:', e); }
        if (!treasuryAddr) {
          treasuryAddr = await resolveTreasuryByConvention(home.name);
          if (treasuryAddr) console.warn('[google-resume] person-treasury reconciled from ANS:', treasuryAddr);
        }
        if (treasuryAddr && isPaymentTemplate(enroll.template)) {
          const cap = BigInt(pc.maxAmountPerCharge);
          const req = enroll.payAmount ? BigInt(enroll.payAmount) : cap;
          payment = {
            treasury: treasuryAddr, payee: pc.payee, asset: pc.asset,
            maxAmountPerCharge: cap, maxAggregate: BigInt(pc.maxAggregate),
            maxRedemptionsPerWindow: pc.maxRedemptionsPerWindow, windowSeconds: pc.windowSeconds, mode: pc.mode,
            chargeNow: true, chargeAmount: req < cap ? req : cap, edition: 'lbsb',
            subscription: enroll.subPeriod ? { periodSeconds: enroll.subPeriod } : undefined,
          };
        } else if (treasuryAddr) {
          // The app's own coin, minted in the plain sign-in — see the matching branch in
          // RecognizedEnroll. This path is the terminal leg of every social re-auth, so leaving it
          // out is how the last payment feature spent months silently doing nothing here.
          payment = coinMandateLeg(relyingApp, treasuryAddr) ?? undefined;
        }
      }
      // spec 345 — a self-vault grant rides this SAME plain sign-in when the client declares one.
      const selfVaultScope = whitelabel.relyingApps.find((a) => a.client_id === enroll.aud)?.self_vault_grant;
      // spec 270 v4 W2 — sign + carry the DEL-001 leaf for the relying app's session key.
      let granted = await givePermission(home, delegate, 'google', { token }, enroll.sessionKey, payment, selfVaultScope);
      if (!granted.ok) return fail(granted.error);
      // spec 278 — turn on the member's encrypted vault during enroll (Google signs via KMS, no
      // gesture; skipped if already bound). Best-effort — must not block the connect.
      try { await activateVaultIfNeeded(home.address, 'google', { token }); } catch { /* non-fatal */ }
      // spec 280 carve-out — self-heal the published connection KIND on every successful social
      // connect (idempotent, gasless, kind-only). Without it a named social home is ambiguous
      // on-chain (C_sub looks like an EOA) and re-entry shows the credential chooser instead of
      // routing straight through the provider.
      void publishSocialConnectionKindIfNeeded(home.address, home.name, 'google', { token });
      let code: string;
      try {
        code = await submitEnrollGrant(grant_id, granted.grant, undefined, granted.sessionDelegation, granted.paymentDelegation, granted.settlementHash, treasuryAddr, granted.pullDelegation, granted.selfVaultGrant);
      } catch (e) {
        // The REUSED standing grant was refused (revoked / no longer verifiable). Clear it and mint
        // fresh ONCE — the single explicit fallback (ADR-0013). A fresh-mint refusal is terminal.
        if (!granted.reused) throw e;
        console.warn('[google-resume] standing grant refused — clearing cache and minting fresh:', e);
        clearStandingGrant(home.address, delegate);
        granted = await givePermission(home, delegate, 'google', { token }, enroll.sessionKey, payment, selfVaultScope);
        if (!granted.ok) return fail(granted.error);
        code = await submitEnrollGrant(grant_id, granted.grant, undefined, granted.sessionDelegation, granted.paymentDelegation, granted.settlementHash, treasuryAddr, granted.pullDelegation, granted.selfVaultGrant);
      }
      // spec 256 — PERSIST the Google custody session as the cross-subdomain SSO cookie. The user just
      // proved control of their Impact home with Google; keeping that token (`.impact-agent.me`, spec 232)
      // means a follow-on home operation — e.g. org-create at `<handle>.impact-agent.me`, which arrives
      // with `?delegate` and therefore SKIPS session restore — can custody the new org with the member's
      // ACTUAL Google credential (server-side KMS deploy) instead of falling through to the passkey path
      // and erroring "your central-auth passkey isn't on this device." Passkey enrolls never reach here.
      setSsoCookie(token, 'Google');
      setFedcmLoginStatus('logged-in'); // FedCM may now call /fedcm/accounts (spec 264)
      const tpl = whitelabel.delegationTemplates[enroll.template];
      recordConnectedApp(home.address, {
        clientId: enroll.aud,
        appName,
        appDomain: appHost,
        logo: relyingApp?.logo,
        canDo: tpl?.canDo ?? [],
        cannotDo: tpl?.cannotDo ?? [],
        grantedAt: Date.now(),
        expiresAt: tpl?.expiryDays ? Date.now() + tpl.expiryDays * 86_400_000 : undefined,
      });
      setPhase('connected');
      clearStash();
      setTimeout(() => deliverEnrollCode(enroll, pending!.popupMode, code), 400);
    } catch (e) {
      fail(e);
    }
  }

  function onDecline() {
    clearStash();
    if (enroll) deliverEnrollCode(enroll, pending!.popupMode, ''); // empty code → relying app treats as cancel
  }

  if (!pending || !enroll) return null;

  if (phase === 'securing') {
    return (
      <Shell>
        <div className="onboarding-busy">
          <WorkingBar />
          <span className="spinner spinner-lg" role="status" aria-label="Securing your home" />
          <p className="onboarding-busy-msg">Securing your home in the {community}…</p>
        </div>
        <p className="onboarding-sub">Signed in with Google — no extra step. This takes a few seconds.</p>
      </Shell>
    );
  }

  if (phase === 'mismatch' && home) {
    const requested = nameLabel(enroll.name);
    return (
      <Shell>
        <BrandShield size={52} />
        <h1 className="onboarding-h1">You already have a home</h1>
        <p className="onboarding-sub">
          This Google account already opens <strong>{home.name}</strong>. You started connecting as{' '}
          <strong>{requested}</strong> — but signing in with Google always brings you to the home it first created
          (one Google account, one home). It can&apos;t be used to make a second.
        </p>
        <button className="btn-primary" onClick={() => setPhase('consent')}>
          Connect {appName} to {home.name}
        </button>
        <button className="btn-ghost onboarding-secondary" onClick={onDecline}>Cancel</button>
        <p className="onboarding-note">
          To use the name “{requested}”, go back to {appName} and secure it with a passkey or wallet instead.
        </p>
      </Shell>
    );
  }

  if (phase === 'name' && home) {
    return (
      <RequiredNameGate
        agent={home.address}
        token={token}
        via="google"
        appName={appName}
        onClaimed={(name) => {
          setHome({ ...home, name });
          setPhase(afterHome());
        }}
        onCancel={onDecline}
      />
    );
  }

  if (phase === 'new-member' && home) {
    return (
      <NewMemberSetup
        person={home.address}
        token={token}
        via="google"
        appName={appName}
        plan={plan}
        onDone={() => setPhase('consent')}
      />
    );
  }

  if (phase === 'granting') {
    return (
      <Shell>
        <div className="onboarding-busy">
          <WorkingBar />
          <span className="spinner spinner-lg" role="status" aria-label="Granting permission" />
          <p className="onboarding-busy-msg">{fmt(c.authorizeStepBusy, { app: appName })}</p>
        </div>
      </Shell>
    );
  }

  if (phase === 'connected') {
    return (
      <Shell>
        <div className="celebrate">
          <BrandShield size={56} />
          <h1 className="onboarding-h1">Permission granted</h1>
        </div>
        <ReceiptCard title={fmt(c.authorizeStepReceipt, { app: appName })} />
        <p className="onboarding-sub">Returning you to {appName}…</p>
        <WorkingBar />
      </Shell>
    );
  }

  if (phase === 'error') {
    return (
      <Shell>
        <h1 className="onboarding-h1">Couldn&apos;t finish</h1>
        <div className="onboarding-error">{error}</div>
        <button className="btn-primary" onClick={onDecline}>Return to {appName}</button>
      </Shell>
    );
  }

  // consent
  // spec: `profile` scope — an app registered to receive the member's human name says so HERE, in
  // the same list as everything else it can do. The setup screen discloses it to a member who is
  // typing the name now; this is what a RETURNING member (whose name is already on file, and who
  // never sees that screen) gets to read before authorizing. No-op for every unscoped app.
  const tpl = withClientConsent(
    withCurrencyConsent(
      withEmailClaimConsent(
        withProfileNameConsent(
          whitelabel.delegationTemplates[enroll.template] ?? {
            canDo: [],
            cannotDo: ['Move your funds', 'Add sign-in methods', 'Change your recovery'],
          },
          relyingApp,
        ),
        relyingApp,
      ),
      relyingApp,
      appName,
    ),
    relyingApp, // last: the client's own wording, when it registered one (no-op otherwise)
    enroll.template,
  );
  return (
    <div className="onboarding-screen">
      <div className="onboarding-card wide">
        <ConsentSheet
          title={fmt(c.authorizeStepTitle, { app: appName })}
          signedInAs={
            // A client that never shows an address or handle gets the email verified in this window, or nothing.
            hidesIdentifiers(relyingApp)
              ? signedInLabel(relyingApp, { email: verifiedEmailFor(home?.address) })
              : home?.name?.trim() || (home?.address ? `${home.address.slice(0, 6)}…${home.address.slice(-4)}` : '')
          }
          signedInBare={hidesIdentifiers(relyingApp) && !!home}
          appName={appName}
          appDomain={appDomain}
          appLogo={relyingApp?.logo}
          appDescription={relyingApp?.description}
          template={tpl}
          authorizeLabel={fmt(c.authorizeStepCta, { app: appName })}
          onAuthorize={onAuthorize}
          onDecline={onDecline}
        />
      </div>
    </div>
  );
}

function Shell({ children }: { children: React.ReactNode }) {
  return (
    <div className="onboarding-screen">
      <div className="onboarding-card">{children}</div>
    </div>
  );
}
