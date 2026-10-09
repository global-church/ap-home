'use client';
import { WorkingBar } from './WorkingBar';
// The onboarding first-run journey, composed from the home ACTIVITIES (src/home/onboarding):
// secure → register → permit. Three understandable activities backed by the fewest device
// prompts: createHomeKey (your device becomes your key) + secureHome (found your home AND
// register your name — one tap, two outcomes) + givePermission (the one separate consent).
//
// spec 257 W4 (name-deferral INTERIM) note: this passkey/wallet bootstrap leaf is reached ONLY
// via the explicit "Use my Impact name" path (EntryExperience → NameStart → journey) or a
// relying-app enroll, so it ALWAYS arrives with a name the member already chose — it is NOT a
// surprise name prompt on the credential-first happy path. The PASSKEY new-user name is
// genuinely LOAD-BEARING: passkeys are subdomain-isolated (RP ID = <label>.impact-agent.me) and
// the bootstrap hops to that subdomain, derived from the name (redirectForPasskey). So a true
// name-free NEW passkey is NOT possible here without the subdomain change — a known, accepted
// limitation; the GOOGLE path (GoogleSecureHome) is the primary no-name flow. The wallet/EOA path
// is not subdomain-bound and COULD auto-assign, but it too is only reached after the member
// explicitly typed a name, so we honour their choice rather than discard it.
import { useEffect, useRef, useState } from 'react';
import type { Address } from '@agenticprimitives/types';
import { createHomeKey, secureHome, openHome, givePermission, createOrganization, personGrantForOrgCreate, continueWithGoogle, continueWithYouVersion, activateVaultIfNeeded, isKmsVia, signHashFor, type Via } from '../../home/onboarding';
import { clearStandingGrant } from '../../lib/grant-cache';
import { readSsoCookie } from '../../lib/sso-cookie';
import { EmailAuthCard } from '../portal/EmailAuthCard';
import { PhoneAuthCard } from '../portal/PhoneAuthCard';
import { fetchProfile, listManagedAgents, resolveTreasuryByConvention } from '../../connect-client';
import { hasWallet } from '../../lib/wallet';
import { clearPasskey, forcePhonePasskeyOnce, isUvMissingError, type DemoPasskey } from '../../lib/passkey';
import { homeLabel, type Home } from '../../home/types';
import { recordConnectedApp } from '../../lib/connected-apps';
import { withMissionRegistry } from '../../lib/mission-registry';
import { whitelabel, fmt, isPaymentTemplate } from '../../whitelabel/config';
import { CENTRAL_AUTH_DOMAIN } from '../../lib/domain';
import { useSession } from '../../context/session';
import type { EnrollApi } from './useEnrollReq';
import { BrandShield } from '../shared/BrandShield';
import { ValueStepList, type ValueStep } from '../shared/ValueStepList';
import { OnboardingProgress } from '../shared/OnboardingProgress';
import { ReceiptCard } from '../shared/ReceiptCard';
import { ConsentSheet } from '../shared/ConsentSheet';
import { displayAppDomain, displayAppName } from './org-chooser-label';
import { NewMemberSetup } from './NewMemberSetup';
import { coinMandateLeg, grantsCoinAtConnect, newMemberPlan, planIsEmpty, withCurrencyConsent, withEmailClaimConsent, withProfileNameConsent } from '../../lib/new-member';
import { hidesIdentifiers, withClientConsent } from '../../whitelabel/client-consent';

export type JourneyVariant = 'enroll-new' | 'enroll-existing' | 'self-serve';

// 'new-member' — first-connect provisioning the relying app declared (`new_member`), between the
// setup receipts and the permission consent. Skipped entirely when the app declared nothing.
type Screen = 'arrival' | 'overview' | 'key-ready' | 'securing' | 'receipts' | 'vault-activate' | 'grant' | 'connected' | 'error' | 'contact' | 'new-member';

export function OnboardingJourney({
  variant,
  name,
  api,
  existingAgent,
  initialVia,
}: {
  variant: JourneyVariant;
  name: string;
  api?: EnrollApi;
  existingAgent?: Address;
  /** For `enroll-existing`: the credential the EXISTING home actually signs with (resolved from its
   *  on-chain credentials by EntryExperience), so a wallet home isn't defaulted to passkey. */
  initialVia?: Via;
}) {
  const { session, openSession } = useSession();
  const c = whitelabel.copy;
  const community = whitelabel.brand.community;
  const appHost = api?.host ?? '';
  const relyingApp = api?.enroll ? whitelabel.relyingApps.find((a) => a.client_id === api.enroll!.aud) : undefined;
  const appName = displayAppName(relyingApp?.name, appHost);
  const appDomain = displayAppDomain(appHost);
  const hasApp = variant !== 'self-serve';
  const base = homeLabel(name);
  // Spec 255 — "the prompt will say impact-agent.me" only makes sense on the real central host (the
  // RP ID IS impact-agent.me there). On dev hosts (localhost / pages.dev) the RP is the dev host, so
  // gate the domain note off, mirroring redirectForPasskey's hostname check (EntryExperience).
  const onCentralHost =
    typeof window !== 'undefined' &&
    (window.location.hostname === CENTRAL_AUTH_DOMAIN || window.location.hostname.endsWith('.' + CENTRAL_AUTH_DOMAIN));

  const [screen, setScreen] = useState<Screen>(variant === 'enroll-existing' ? 'grant' : 'arrival');
  const [busy, setBusy] = useState<string | null>(null);
  const [securingMsg, setSecuringMsg] = useState<string>('');
  const [key, setKey] = useState<DemoPasskey | null>(null);
  const [via, setVia] = useState<Via>(initialVia ?? 'passkey'); // the credential the member secures/opens with
  const [home, setHome] = useState<Home | null>(existingAgent ? { address: existingAgent, name } : null);
  // Credential methods offered for securing a home: config-enabled ∩ device capability.
  // passkey + google are always available; wallet needs an injected provider.
  const methods = whitelabel.onboarding.credentialMethods.filter((m) => (m === 'wallet' ? hasWallet() : true));
  const [error, setError] = useState<string>('');
  const [contactKind, setContactKind] = useState<'email' | 'phone'>('email');
  const failBack = useRef<Screen>('overview');

  // ── First-connect provisioning (whitelabel `new_member`) ────────────────────────────────────
  // Only a NEW home in a relying-app enroll qualifies: `enroll-existing` is someone who already
  // has a home (and possibly a treasury and a name), and self-serve has no app to declare anything.
  //
  // It also needs a HOME SESSION, because creating an agent and writing to the member's own vault
  // are both authorized by one. The email/phone leg of this journey has one (the OTP cards open it
  // themselves); the passkey/wallet leg deliberately does NOT open a session before the grant, and
  // manufacturing one here would cost a second device prompt in the middle of a ceremony that
  // already has two. So that leg falls through to the consent unchanged — see the report/README
  // note: those members claimed a handle on the way in (the named journey requires one), so they
  // are not the "shows as a truncated address" case, and /treasuries remains the way to open an
  // account by hand.
  const relyingPlan = newMemberPlan(relyingApp);
  const setupToken = session?.token ?? readSsoCookie()?.token ?? '';
  const newMemberNext = (): Screen =>
    variant === 'enroll-new' && !planIsEmpty(relyingPlan) && setupToken ? 'new-member' : 'grant';

  useEffect(() => {
    if (!hasApp || screen !== 'contact' || !session?.token) return;
    let cancelled = false;
    void (async () => {
      try {
        const profile = await fetchProfile(session.token);
        const addr = profile?.agent?.split(':').pop();
        if (!addr || !/^0x[0-9a-fA-F]{40}$/.test(addr)) return;
        if (cancelled) return;
        setHome({ address: addr as Address, name: profile?.name || name });
        setVia(contactKind);
        // The OTP card just bootstrapped (or resolved) this home and opened the session, so this is
        // the one moment in this journey where the new-member gate has everything it needs.
        setScreen(newMemberNext());
      } catch (e) {
        if (!cancelled) fail(e, 'contact');
      }
    })();
    return () => { cancelled = true; };
  }, [contactKind, hasApp, name, screen, session?.token]);

  // Surface the real reason — secureHome/etc. return error STRINGS, not Error objects.
  const fail = (e: unknown, back: Screen) => {
    setBusy(null);
    setError(e instanceof Error ? e.message : typeof e === 'string' ? e : 'Something went wrong');
    failBack.current = back;
    setScreen('error');
  };

  // Securing your home is two confirmations (the subregistry registers your name from YOUR
  // Smart Agent — one-name-per-caller — so a relayer can't do it for you). Gesture 1 mints
  // your key; gesture 2 founds your home + claims your name in one userOp.

  // Passkey, gesture 1 — create your key (a user gesture for WebAuthn create).
  async function onCreateKey() {
    setVia('passkey');
    setBusy('Confirm with your device…');
    try {
      setKey(await createHomeKey(name));
      setBusy(null);
      setScreen('key-ready');
    } catch (e) {
      fail(e, 'overview');
    }
  }

  // Passkey, gesture 2 — found your home + register your name in one signed userOp (rich wait).
  async function onSecureHome() {
    if (!key) return;
    setSecuringMsg(`Founding ${base} as your home and registering your name in the ${community}…`);
    setScreen('securing');
    try {
      const res = await secureHome(key, name, 'passkey', undefined, setSecuringMsg);
      if (!res.ok) return fail(res.error, 'key-ready');
      setHome(res.home);
      setScreen('receipts');
    } catch (e) {
      fail(e, 'key-ready');
    }
  }

  // Google — redirects out to the broker, then returns (?code) to the secure-home step. In a
  // relying-app enrollment we stash the enroll request so the post-redirect resume can finish the
  // grant + deliver the code back to the app (the URL params are lost across the Google redirect).
  function onGoogle() {
    const stash =
      hasApp && api?.enroll
        ? JSON.stringify({ enroll: api.enroll, popupMode: api.popupMode, name })
        : undefined;
    // Warn a popup opener we're leaving for Google (COOP severs the opener) so it waits for the
    // relay channel rather than treating the severed `popup.closed` as a cancel. No-op otherwise.
    api?.postToOpener({ type: 'AC_PROGRESS', msg: 'Continuing with Google…', idp: true });
    continueWithGoogle(name, stash);
  }

  // Email/phone — the OTP cards secure a KMS home; stash the journey's CHOSEN NAME first (the same
  // `pendingHomeName` mechanism the Google redirect uses) so `secureHomeNoName` claims it — without
  // the stash the chosen name was silently dropped and the home came out nameless (rich-phone3).
  function openContact(kind: 'email' | 'phone') {
    try {
      if (name) sessionStorage.setItem('pendingHomeName', name);
    } catch { /* storage blocked — the member can claim the name from the Naming page */ }
    setContactKind(kind);
    setScreen('contact');
  }

  // YouVersion — identical redirect machinery to Google (shared post-redirect resume; only the IdP differs).
  function onYouVersion() {
    const stash =
      hasApp && api?.enroll
        ? JSON.stringify({ enroll: api.enroll, popupMode: api.popupMode, name })
        : undefined;
    api?.postToOpener({ type: 'AC_PROGRESS', msg: 'Continuing with YouVersion…', idp: true });
    continueWithYouVersion(name, stash);
  }

  // Wallet — no key-create step; the wallet prompts (SIWE + deploy/claim) ARE the gestures.
  async function onSecureWithWallet() {
    setVia('wallet');
    setSecuringMsg(`Securing ${base} as your home with your wallet…`);
    setScreen('securing');
    try {
      const res = await secureHome(null, name, 'wallet');
      if (!res.ok) return fail(res.error, 'overview');
      setHome(res.home);
      setScreen('receipts');
    } catch (e) {
      fail(e, 'overview');
    }
  }

  // After the receipts: relying-app → permission consent; self-serve → activate your private vault.
  async function onContinue() {
    if (hasApp) {
      setScreen(newMemberNext());
      return;
    }
    if (!home) return;
    setError('');
    setScreen('vault-activate');
  }

  // Self-serve final step — turn on the per-person encrypted vault (spec 278). One signature with
  // the SAME credential (passkey/wallet locally; Google via KMS). Provision + delegate discovery are
  // system-supplied. Fail-soft: the member can skip and activate later from /profile, so a vault
  // hiccup never traps them out of their freshly-created home.
  async function onActivateVault() {
    if (!home) return;
    setBusy(via === 'google' ? 'Activating your private vault…' : `Activating your private vault — confirm with your ${via}…`);
    setError('');
    // B3 — secureHome→activatePersonPlanes already bound the vault, so use the is-bound-gated variant here:
    // it SKIPS when already bound (no redundant re-provision + re-bind = no extra wallet prompts), and still
    // binds if the earlier fail-soft bind didn't land.
    const act = await activateVaultIfNeeded(home.address, via);
    if (!act.ok) {
      setBusy(null);
      setError(`Couldn't activate your vault (${act.error}). You can retry, or skip and turn it on later from your profile.`);
      return;
    }
    await proceedToHome();
  }

  async function onSkipVault() {
    setError('');
    await proceedToHome();
  }

  async function proceedToHome() {
    if (!home) return;
    setBusy('Opening your home…');
    try {
      const out = await openHome(home.name, via === 'wallet' ? 'wallet' : 'passkey');
      if (!out.ok) return fail(out.error, 'vault-activate');
      await openSession(out.token, via, true);
    } catch (e) {
      fail(e, 'vault-activate');
    }
  }

  // ③ — give the app permission to your resources (the one separate consent + signature).
  async function onGivePermission() {
    if (!api?.enroll || !home) return;
    setBusy(fmt(c.authorizeStepBusy, { app: appName }));
    api.postToOpener?.({ type: 'AC_PROGRESS', msg: 'Granting permission…' });
    try {
      // SEC-001: server-mint the enrollment grant FIRST so the ceremony runs against the
      // registry-derived delegate (not the URL-supplied `api.enroll.delegate`, which is
      // attacker-controllable). The supplied delegation's `delegate` MUST equal what the
      // server bound — /oidc/grant rejects otherwise.
      const { grant_id, delegate } = await api.beginGrant(home.name);
      // spec 272/243 — x402-pay: authorize a capped payment delegation from the member's PRE-CREATED
      // person-treasury (approach A — the treasury is made once in the Portal; we don't deploy here).
      // Resolve it via the member's own agent tree, then sign `treasury → lbsb-treasury` in the SAME
      // ceremony (same credential). If they have no treasury yet, connect proceeds without payment —
      // they create a personal treasury in their home and reconnect.
      // Derived from `givePermission` rather than restated — see the matching note in RecognizedEnroll.
      let payment: Parameters<typeof givePermission>[5];
      const pc = relyingApp?.paymentConfig;
      // The member's person-treasury (if any), surfaced to the relying app so it can gate financial ops.
      // Resolved only on the x402-pay path here (it opens the home anyway); for plain site-login the
      // recognized fast-path (RecognizedEnroll) resolves it for free, so we don't force a re-auth gesture
      // just to read it. A first-run member has no treasury → null.
      let treasuryAddr: Address | null = null;
      // Only an EXISTING member can have a person-treasury (a brand-new first-run member just made their
      // home and has none yet — they set up payment later from the Portal, then reconnect). Guarding on
      // `existingAgent` avoids a wasted re-auth for first-run x402-pay connects. openHome here is
      // wallet/passkey only; SOCIAL (KMS) members connect through RecognizedEnroll (which already has a
      // session token + charges via signHashFor — all custodians).
      if (isPaymentTemplate(api.enroll.template) && pc && existingAgent && (via === 'passkey' || via === 'wallet' || isKmsVia(via))) {
        // wallet/passkey re-open the home for a fresh token; a social/KMS member reuses the
        // cross-subdomain SSO session token (openHome is wallet/passkey-only).
        const opened = isKmsVia(via)
          ? (() => { const sso = readSsoCookie(); return sso?.token ? ({ ok: true as const, token: sso.token }) : ({ ok: false as const }); })()
          : await openHome(home.name, via as 'passkey' | 'wallet');
        if (opened.ok) {
          const treasury = (await listManagedAgents(opened.token)).find((a) => a.kind === 'person-treasury');
          treasuryAddr = (treasury?.agent as Address) ?? null;
          if (treasury) {
            payment = {
              treasury: treasury.agent as Address,
              payee: pc.payee,
              asset: pc.asset,
              maxAmountPerCharge: BigInt(pc.maxAmountPerCharge),
              maxAggregate: BigInt(pc.maxAggregate),
              maxRedemptionsPerWindow: pc.maxRedemptionsPerWindow,
              windowSeconds: pc.windowSeconds,
              mode: pc.mode,
              chargeNow: true,
              // tier amount (enroll.payAmount) capped by the registered per-charge max; default = max.
              chargeAmount: (() => { const cap = BigInt(pc.maxAmountPerCharge); const req = api.enroll!.payAmount ? BigInt(api.enroll!.payAmount) : cap; return req < cap ? req : cap; })(),
              edition: 'lbsb',
              // spec 272 recurring — a SUBSCRIPTION connect (sub_period set): also mint a standing pull mandate.
              subscription: api.enroll!.subPeriod ? { periodSeconds: api.enroll!.subPeriod } : undefined,
            };
          }
        }
      }
      // THE APP'S OWN COIN (`new_member.currency.spend_grant`), minted in this same plain sign-in.
      //
      // A SEPARATE BRANCH from the x402 one above because it answers a different question about a
      // different member: that one needs an EXISTING member with an existing account (`existingAgent`),
      // because a first-run member had none. This one runs for a member the new-member setup screen
      // JUST opened an account for — which is the whole point of folding the grant into the first
      // connect — so it reads the tree with the session that screen used rather than guarding on
      // having met them before.
      if (!payment && grantsCoinAtConnect(relyingApp) && setupToken) {
        try {
          const tre = (await listManagedAgents(setupToken)).find((a) => a.kind === 'person-treasury');
          treasuryAddr = (tre?.agent as Address) ?? treasuryAddr;
          payment = coinMandateLeg(relyingApp, treasuryAddr) ?? undefined;
        } catch (e) {
          // No mandate is a recoverable state (the app asks for one later); a failed connect is not.
          console.warn('[connect] app-coin mandate skipped — account unreadable:', e);
        }
      }
      // spec 270 v4 W2 — sign the DEL-001 leaf for the relying app's session-key address (from the
      // /authorize params) + submit it alongside the grant; /token returns it to the relying app.
      // A social/KMS member who lands in the journey (recognition missed — e.g. the session was
      // cleared by a forced-chooser ceremony) still needs a custody session for the server-side KMS
      // signer: recover the home-session token from the cross-subdomain SSO cookie. Without it,
      // signHashFor fails closed ('granting with an OIDC home needs a custody session').
      const kmsAuth = isKmsVia(via) ? (() => { const sso = readSsoCookie(); return sso?.token ? { token: sso.token } : undefined; })() : undefined;
      // ORG-CREATE reached through the journey (passkey / wallet / named path): this used to run the
      // bare site-login pipeline and deliver a code with NO org — the relying app then errored "no
      // organization returned from your home" and asked the member to connect AGAIN. Deploy (or
      // connect) the org and submit the grant WITH the org payload, exactly like RecognizedEnroll.
      if (api.enroll.template === 'org-create') {
        const orgBase = api.enroll.orgBase;
        const existingOrg = api.enroll.existingOrg;
        if (!orgBase && !existingOrg) {
          return fail(
            'This connect needs an organization. Start again from the app and name your organization there.',
            'grant',
          );
        }
        const created = await createOrganization(home, orgBase ?? '', delegate, via, kmsAuth, {
          purpose: api.enroll.purpose,
          requestedBy: api.enroll.aud,
          grantOrg: api.enroll.grantOrg,
          existingOrg,
        });
        if (!created.ok) return fail(created.error, 'grant');
        // THE MISSION REGISTRY step, when the app asked for it — the same one the recognized ceremony runs, so a
        // brand-new member creating their first organization in this trip is listed too.
        setBusy('Listing the organization in the registry…');
        const listed = await withMissionRegistry({ enroll: api.enroll, relyingApp, org: created.org, steward: home.address, via, auth: kmsAuth, signHashFor: (v, s, a) => signHashFor(v as Via, s, a), onStep: (label) => setBusy(label) });
        if (!listed.ok) return fail(listed.error, 'grant');
        created.org = listed.org;
        const proved = await personGrantForOrgCreate(home, delegate, via, kmsAuth, created, api.enroll.sessionKey);
        if (!proved.ok) return fail(proved.error, 'grant');
        const orgCode = await api.submitGrant(grant_id, proved.grant, proved.org, proved.sessionDelegation);
        const orgTpl = whitelabel.delegationTemplates[api.enroll.template];
        recordConnectedApp(home.address, {
          clientId: api.enroll.aud,
          appName,
          appDomain: appHost,
          logo: relyingApp?.logo,
          canDo: orgTpl?.canDo ?? [],
          cannotDo: orgTpl?.cannotDo ?? [],
          grantedAt: Date.now(),
          expiresAt: orgTpl?.expiryDays ? Date.now() + orgTpl.expiryDays * 86_400_000 : undefined,
        });
        setBusy(null);
        setScreen('connected');
        setTimeout(() => api.deliverCode(orgCode), 400);
        return;
      }
      // spec 345 — a self-vault grant rides this SAME plain sign-in when the client declares one.
      const selfVaultScope = relyingApp?.self_vault_grant;
      let granted = await givePermission(home, delegate, via, kmsAuth, api.enroll?.sessionKey, payment, selfVaultScope);
      if (!granted.ok) return fail(granted.error, 'grant');
      // spec 278 — also turn on the member's encrypted vault while enrolling (skipped if already
      // bound, so returning members aren't re-prompted). Best-effort: a vault hiccup must NOT block
      // connecting to the app — they can also activate later from /profile.
      setBusy('Activating your private vault…');
      try { await activateVaultIfNeeded(home.address, via); } catch { /* non-fatal */ }
      setBusy(fmt(c.authorizeStepBusy, { app: appName }));
      let code: string;
      try {
        code = await api.submitGrant(grant_id, granted.grant, undefined, granted.sessionDelegation, granted.paymentDelegation, granted.settlementHash, treasuryAddr, granted.pullDelegation, granted.selfVaultGrant);
      } catch (e) {
        // The REUSED standing grant was refused (revoked / no longer verifiable). Clear it and mint
        // fresh ONCE — the single explicit fallback (ADR-0013). A fresh-mint refusal is terminal.
        if (!granted.reused) throw e;
        console.warn('[journey] standing grant refused — clearing cache and minting fresh:', e);
        clearStandingGrant(home.address, delegate);
        granted = await givePermission(home, delegate, via, kmsAuth, api.enroll?.sessionKey, payment, selfVaultScope);
        if (!granted.ok) return fail(granted.error, 'grant');
        code = await api.submitGrant(grant_id, granted.grant, undefined, granted.sessionDelegation, granted.paymentDelegation, granted.settlementHash, treasuryAddr, granted.pullDelegation, granted.selfVaultGrant);
      }
      const tpl = whitelabel.delegationTemplates[api.enroll.template];
      recordConnectedApp(home.address, {
        clientId: api.enroll.aud,
        appName,
        appDomain: appHost,
        logo: relyingApp?.logo,
        canDo: tpl?.canDo ?? [],
        cannotDo: tpl?.cannotDo ?? [],
        grantedAt: Date.now(),
        expiresAt: tpl?.expiryDays ? Date.now() + tpl.expiryDays * 86_400_000 : undefined,
      });
      setBusy(null);
      setScreen('connected');
      setTimeout(() => api.deliverCode(code), 400);
    } catch (e) {
      fail(e, 'grant');
    }
  }

  if (busy) {
    return (
      <Frame>
        <div className="onboarding-busy">
          <WorkingBar />
          <span className="spinner spinner-lg" role="status" aria-label="Working" />
          <p className="onboarding-busy-msg">{busy}</p>
          <p className="onboarding-busy-sub">Your device may ask you to confirm. This takes a few seconds.</p>
        </div>
      </Frame>
    );
  }

  if (screen === 'error') {
    // The Windows Microsoft-synced passkey store skipped user verification (UV=0 — rejected by the
    // custody gate). Retrying the same store fails identically, so the primary recovery is a FRESH
    // passkey created on a phone (QR / hybrid), whose authenticator attests UV properly. Nothing was
    // deployed, so dropping the local cache and re-creating is safe.
    const uvSkipped = isUvMissingError(new Error(error));
    return (
      <Frame>
        <h1 className="onboarding-h1">Something went wrong</h1>
        <div className="onboarding-error">{error}</div>
        <p className="onboarding-sub">Nothing was changed. You can try again.</p>
        {uvSkipped && (
          <button
            className="btn-primary"
            onClick={() => {
              clearPasskey(); // drop the UV-less credential's cache — the retry must not reuse it
              forcePhonePasskeyOnce(); // steer the next create() to a phone (QR) / security key
              setError('');
              setScreen(failBack.current);
            }}
          >
            Try again with a phone passkey
          </button>
        )}
        {/* Plain retry: after a UV skip, ALSO drop the cache so the full picker reopens (the user
            can pick this device again — fine where Hello isn't MS-account-synced — or a phone). */}
        <button className={uvSkipped ? 'btn-ghost onboarding-secondary' : 'btn-primary'} onClick={() => { if (uvSkipped) clearPasskey(); setError(''); setScreen(failBack.current); }}>Try again</button>
        {api && <button className="btn-ghost onboarding-secondary" onClick={api.denyEnroll}>Cancel</button>}
      </Frame>
    );
  }

  if (screen === 'arrival') {
    return (
      <Frame>
        <BrandShield size={60} />
        <h1 className="onboarding-h1">{c.arrivalTitle}</h1>
        <p className="onboarding-sub">{c.arrivalBody}</p>
        <div className="name-chip">
          <span className="name-chip-full">{whitelabel.brand.name} Community</span>
          <span className="name-chip-label">{base} home</span>
        </div>
        <button className="btn-primary" onClick={() => setScreen('overview')}>Get started</button>
      </Frame>
    );
  }

  if (screen === 'overview') {
    const steps: ValueStep[] = [
      { id: 'secure', title: c.portalStepTitle, body: c.portalStepValue, status: 'active' },
      { id: 'register', title: c.communityStepTitle, body: c.communityStepValue, status: 'pending' },
      ...(hasApp
        ? [{ id: 'permit', title: fmt(c.authorizeStepTitle, { app: appName }), body: fmt(c.authorizeStepValue, { app: appName }), status: 'pending' as const }]
        : [{ id: 'later', title: 'Give apps permission later', body: `From your home you can give missional community apps permission anytime.`, status: 'pending' as const }]),
    ];
    return (
      <Frame>
        <h1 className="onboarding-h1">{c.overviewTitle}</h1>
        <ValueStepList steps={steps} />
        <p className="onboarding-note">Choose one way to secure your named home — only you will be able to open it.</p>
        {/* Spec 255 W3.1 — pre-create explainer. Renders ONLY when passkey is an offered method (so it
            never appears on a Google-only screen) and sits directly above the passkey CTA. */}
        {methods.includes('passkey') && (
          <div className="securing-explainer pre-prompt-explainer">
            <div className="securing-explainer-title">Your device becomes your key</div>
            <p>
              A passkey is a small secret your device stores — confirmed with your fingerprint, face, or PIN.
              No password to remember, and nothing leaves this device.
            </p>
            <p className="securing-wait">This is a one-time step. You will not create this key again.</p>
            {hasApp && (
              <p className="securing-wait">You came from {appName} — after setup you&apos;ll return there automatically.</p>
            )}
          </div>
        )}
        <div className="method-choice" style={{ alignItems: 'stretch' }}>
          {methods.includes('passkey') && (
            <button className="btn-primary" onClick={onCreateKey}>
              {c.portalStepCreateCta}
              <span style={{ display: 'block', fontSize: '.78rem', fontWeight: 500, opacity: .86, marginTop: 3 }}>Best for this device</span>
            </button>
          )}
          {methods.includes('google') && (
            // Self-serve → returns to GoogleSecureHome. Relying-app enrollment → onGoogle stashes
            // the enroll request so the post-redirect resume finishes the grant + returns the code.
            <button className={methods.includes('passkey') ? 'btn-ghost onboarding-secondary' : 'btn-primary'} onClick={onGoogle}>Continue with Google</button>
          )}
          {methods.includes('youversion') && (
            <button className="btn-ghost onboarding-secondary" onClick={onYouVersion}>Continue with YouVersion</button>
          )}
          {/* Email / phone (specs 319/320): OTP-verified, KMS-custodied homes. In relying-app
              enrollment, completion returns to this journey and continues to the permission step. */}
          {methods.includes('email') && (
            <button className="btn-ghost onboarding-secondary" onClick={() => { openContact('email'); }}>
              Continue with email
            </button>
          )}
          {methods.includes('wallet') && (
            <button className="btn-ghost onboarding-secondary" onClick={onSecureWithWallet}>Secure with a wallet</button>
          )}
          {methods.includes('phone') && (
            <button className="btn-ghost onboarding-secondary" onClick={() => { openContact('phone'); }}>
              Continue with phone
            </button>
          )}
        </div>
      </Frame>
    );
  }

  if (screen === 'contact') {
    // Email/phone secure-home (specs 319/320): the OTP card verifies the contact, bootstraps the
    // KMS-custodied home, and opens the session — the session context then routes into the portal.
    return (
      <Frame>
        <h1 className="onboarding-h1">{contactKind === 'email' ? 'Continue with email' : 'Continue with phone'}</h1>
        <p className="onboarding-sub">
          We send you a one-time code. Your home is secured by a managed key tied to your verified{' '}
          {contactKind === 'email' ? 'email address' : 'phone number'} — no password, nothing to install.
        </p>
        <div style={{ textAlign: 'left', margin: '0 auto', maxWidth: 420 }}>
          {contactKind === 'email' ? <EmailAuthCard /> : <PhoneAuthCard />}
        </div>
        <button className="btn-ghost onboarding-secondary" onClick={() => setScreen('overview')}>← Back</button>
      </Frame>
    );
  }

  if (screen === 'key-ready') {
    return (
      <Frame>
        {/* Spec 255 W3.4 — same value step (① secure your home) but the gesture label is now the
            distinct "Approve your setup", not a repeat of "Create your passkey". */}
        <OnboardingProgress total={hasApp ? 3 : 2} current={1} label={c.portalStepCta} />
        {/* W1.2/W4.1 — receipt for the passkey just created (gesture 1). */}
        <ReceiptCard title={c.portalKeyCreatedReceiptTitle} body={c.portalKeyCreatedReceiptBody} />
        <h1 className="onboarding-h1">One more — approve your setup</h1>
        <p className="onboarding-sub">
          This step is different from the last one. You are not creating anything new — you are using the
          key you just created to approve what happens next.
        </p>
        {/* W3.2 — pre-deploy explainer block: exactly what this approval does + the domain pre-empt. */}
        <div className="securing-explainer pre-prompt-explainer">
          <div className="securing-explainer-title">What you&apos;re approving</div>
          <ul className="securing-points">
            <li><span aria-hidden="true">✓</span> Your home starts on the network</li>
            <li><span aria-hidden="true">✓</span> Your name {base} is reserved — permanently yours</li>
            {hasApp && (
              <li><span aria-hidden="true">✓</span> You return to {appName} to give it permission next</li>
            )}
          </ul>
          {onCentralHost && (
            <p className="securing-wait">
              The prompt will say &lsquo;{CENTRAL_AUTH_DOMAIN}&rsquo; — that is this page.
            </p>
          )}
        </div>
        <button className="btn-primary" onClick={onSecureHome}>{c.portalStepCta}</button>
      </Frame>
    );
  }

  if (screen === 'securing') {
    return (
      <Frame>
        <OnboardingProgress total={hasApp ? 3 : 2} current={1} label={c.portalStepCta} />
        <div className="onboarding-busy">
          <WorkingBar />
          <span className="spinner spinner-lg" role="status" aria-label="Securing your home" />
          <p className="onboarding-busy-msg">{securingMsg}</p>
        </div>
        <div className="securing-explainer">
          <div className="securing-explainer-title">While we set this up</div>
          <p>
            We&apos;re founding <strong>{base}</strong> as your home in the {community} and registering your name —
            permanently yours, on a public record no company controls.
          </p>
          <ul className="securing-points">
            <li><span aria-hidden="true">✓</span> Yours alone — only your device can open it</li>
            <li><span aria-hidden="true">✓</span> A name others in the {community} can find and trust</li>
            <li><span aria-hidden="true">✓</span> No password, nothing to lose — just this device confirms it's you</li>
          </ul>
          <p className="securing-wait">This usually takes about 15 seconds — you can stay on this page.</p>
        </div>
      </Frame>
    );
  }

  if (screen === 'receipts') {
    const registered = home ? homeLabel(home.name) : base;
    return (
      <Frame>
        <OnboardingProgress total={3} current={2} label={c.communityStepTitle} />
        <div className="celebrate">
          <BrandShield size={52} />
          <h1 className="onboarding-h1">Your home is ready</h1>
        </div>
        <ReceiptCard title={c.portalStepReceipt} body="Secured ✓ · yours alone" />
        <ReceiptCard title={fmt(c.communityStepReceipt, { name: registered })} body={`You're known as ${registered}`} />
        <button className="btn-primary" onClick={onContinue}>Continue</button>
      </Frame>
    );
  }

  if (screen === 'vault-activate') {
    return (
      <Frame>
        <OnboardingProgress total={3} current={3} label="Activate your vault" />
        <div className="celebrate">
          <BrandShield size={52} />
          <h1 className="onboarding-h1">Activate your private vault</h1>
        </div>
        <p className="onboarding-sub">
          One sign turns on your private, end-to-end encrypted vault. Your profile and data are sealed
          under your own key — only you authorize who can read them, and you can revoke it anytime.
        </p>
        {error && <p className="onboarding-hint taken">{error}</p>}
        <button className="btn-primary" onClick={onActivateVault} disabled={!!busy}>
          {busy ?? 'Sign + activate my vault'}
        </button>
        <button className="btn-ghost onboarding-secondary" onClick={onSkipVault} disabled={!!busy}>
          Skip for now
        </button>
      </Frame>
    );
  }

  if (screen === 'new-member' && home && setupToken) {
    // Renders nothing and advances immediately when the member already has what the app asked for,
    // so this can only ever DELAY the consent, never replace it.
    return (
      <NewMemberSetup
        person={home.address}
        token={setupToken}
        via={via}
        appName={appName}
        plan={relyingPlan}
        onDone={() => setScreen('grant')}
      />
    );
  }

  // `new-member` falls through to HERE when the session that authorized it has gone (the only way
  // to lose `setupToken` mid-flow). Losing a setup screen must never mean losing the consent — the
  // member connects, and the next connect asks again.
  if ((screen === 'grant' || screen === 'new-member') && api?.enroll) {
    const tpl = withClientConsent(
      withCurrencyConsent(
        withEmailClaimConsent(
          withProfileNameConsent(
            whitelabel.delegationTemplates[api.enroll.template] ?? { canDo: [], cannotDo: ['Move your funds', 'Add sign-in methods', 'Change your recovery'] },
            relyingApp,
          ),
          relyingApp,
        ),
        relyingApp,
        appName,
      ),
      relyingApp, // last: the client's own wording, when it registered one (no-op otherwise)
      api.enroll.template,
    );
    return (
      <Frame wide>
        <OnboardingProgress total={3} current={3} label="Give permission" />
        <ConsentSheet
          title={fmt(c.authorizeStepTitle, { app: appName })}
          // A client that never shows a handle (Gather27) names nobody here; this path has no verified email.
          signedInAs={hidesIdentifiers(relyingApp) ? undefined : name?.trim() || undefined}
          signedInBare={hidesIdentifiers(relyingApp)}
          appName={appName}
          appDomain={appDomain}
          appLogo={relyingApp?.logo}
          appDescription={relyingApp?.description}
          template={tpl}
          authorizeLabel={fmt(c.authorizeStepCta, { app: appName })}
          onAuthorize={onGivePermission}
          onDecline={api.denyEnroll}
        />
      </Frame>
    );
  }

  if (screen === 'connected') {
    return (
      <Frame>
        <div className="celebrate">
          <BrandShield size={64} />
          <h1 className="onboarding-h1">Permission granted</h1>
        </div>
        <ReceiptCard title={fmt(c.authorizeStepReceipt, { app: appName })} />
        <p className="onboarding-sub">Returning you to {appName}…</p>
        <WorkingBar />
      </Frame>
    );
  }

  return null;
}

function Frame({ children, wide = false }: { children: React.ReactNode; wide?: boolean }) {
  return (
    <div className="onboarding-screen">
      <div className={`onboarding-card${wide ? ' wide' : ''}`}>{children}</div>
    </div>
  );
}
