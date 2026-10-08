'use client';
import { HomeFooter } from '../shared/HomeFooter';
import { WorkingBar } from './WorkingBar';
// Full-bleed entry experience shown by the portal gate when NOT authed (or mid relying-app
// enrollment). Routes: relying-app enroll (new / existing / org-create) and self-serve
// (onboarding / sign-in). The onboarding journey itself lives in <OnboardingJourney/>.
import { useEffect, useRef, useState } from 'react';
import type { Address } from '@agenticprimitives/types';
import { openHome, createOrganization, createGovernedWorkspace, personGrantForOrgCreate, continueWithGoogle, continueWithYouVersion, resolveVia, signHashFor, secureHomeWalletNoName, type Via, type Auth } from '../../home/onboarding';
import { passkeyLogin, fetchProfile, siweLogin, claimName, resolveHomeNameForLabel } from '../../connect-client';
import { loadPasskey } from '../../lib/passkey';
import { hasWallet } from '../../lib/wallet';
import { initRemoteSigner } from '../../lib/remote-signer';
import { whitelabel } from '../../whitelabel/config';
import { knownRelyingClient } from '../../lib/relying-clients';
import { hasSessionHandoff, useSession } from '../../context/session';
import { EmailAuthCard } from '../portal/EmailAuthCard';
import { PhoneAuthCard } from '../portal/PhoneAuthCard';
import { readSsoCookie } from '../../lib/sso-cookie';
import { CENTRAL_AUTH_DOMAIN, nameLabel, personalAuthOrigin, toAgentName, parseAgentSubdomain } from '../../lib/domain';

const googleEnabled = whitelabel.onboarding.credentialMethods.includes('google');
const youversionEnabled = whitelabel.onboarding.credentialMethods.includes('youversion');
const walletEnabled = whitelabel.onboarding.credentialMethods.includes('wallet');
const passkeyEnabled = whitelabel.onboarding.credentialMethods.includes('passkey');
const emailEnabled = whitelabel.onboarding.credentialMethods.includes('email');
const phoneEnabled = whitelabel.onboarding.credentialMethods.includes('phone');
import { useEnrollReq, type EnrollApi, isCeremonyTemplate, isDeployTemplate } from './useEnrollReq';
import { OnboardingJourney } from './OnboardingJourney';
import { DemoPeopleFold } from './DemoPeopleFold';
import { RecognizedEnroll } from './RecognizedEnroll';
import { CeremonyProgress } from './CeremonyProgress';
import { OrgChooser, type OrgChoice } from './OrgChooser';
import { BrandShield } from '../shared/BrandShield';
import { ConsentSheet } from '../shared/ConsentSheet';
import { ReceiptCard } from '../shared/ReceiptCard';
import { HomeResolvedView } from './HomeResolvedView';
import { AgentReachFold } from './AgentReachFold';
import { socialButtonsForNamedHome } from '../../lib/named-home-door';
import { RequiredNameGate } from './RequiredNameGate';
import { NewMemberSetup } from './NewMemberSetup';
import { isNewHomeMoment, newMemberPlan, planIsEmpty, type NewMemberPlan } from '../../lib/new-member';
import { displayAppDomain, displayAppName } from './org-chooser-label';
import { parseEnrollReq } from './useEnrollReq';
import { clientCopy, clientProgressText, orgCreateText, withClientConsent } from '../../whitelabel/client-consent';

interface NameInfo { exists?: boolean; agent?: Address; deployed?: boolean; hasEoa?: boolean; hasPasskey?: boolean; connectionKind?: string | null; connectionAddress?: string | null; passkeySigningAvailable?: boolean | null }
/** Human label for the owner-published connection kind (spec 280) — guides which button to use. */
const CONNECTION_LABEL: Record<string, string> = { wallet: 'wallet', google: 'Google', youversion: 'YouVersion', passkey: 'passkey', email: 'email', phone: 'phone', multi: 'any of the below' };
async function nameInfo(name: string): Promise<NameInfo> {
  try {
    return (await (await fetch(`/connect/name-info?name=${encodeURIComponent(name)}`)).json()) as NameInfo;
  } catch {
    return {};
  }
}

/** CAIP-10 tail (`eip155:<chain>:0x…`) → `0x…`, or null. Mirrors RecognizedEnroll / context/session. */
function addressOf(caip10: string | undefined): Address | null {
  if (!caip10) return null;
  const tail = caip10.split(':').pop();
  return tail && /^0x[0-9a-fA-F]{40}$/.test(tail) ? (tail as Address) : null;
}

/** The credential an EXISTING home actually signs with, from its on-chain credentials (name-info) — so
 *  a wallet-only home is opened/granted with the WALLET, not the passkey default. A social/KMS home's
 *  custodian C_sub LOOKS like an EOA on-chain, so `connectionKind` (the name-info's off-chain record of
 *  how the home actually connects) MUST win over the hasEoa guess — otherwise a Google home reaching the
 *  name path (e.g. after a pin-mismatch cleared the session) gets MetaMask + "isn't a custodian". */
function viaForHome(info: NameInfo): Via {
  const ck = (info.connectionKind ?? '').toLowerCase();
  if (ck === 'google' || ck === 'youversion' || ck === 'email' || ck === 'phone') return ck as Via;
  return info.hasPasskey ? 'passkey' : info.hasEoa ? 'wallet' : 'passkey';
}

/** Would resolving this name actually run a PASSKEY ceremony? Only then does the RP ID matter, and
 *  only then is the hop to `<label>.impact-agent.me` (redirectForEnrollName) worth a page load.
 *  A NEW name may bootstrap a passkey home → hop. An EXISTING home that has no passkey on-chain
 *  signs with a wallet or server-side KMS — both origin-agnostic — so it resolves in place on the
 *  apex, which is also where the enroll's consent belongs (no mid-ceremony origin jump). */
function needsPasskeyOrigin(info: NameInfo): boolean {
  if (!(info.exists && info.agent)) return true; // new name — the journey may create a passkey
  return !!info.hasPasskey;
}

// Subdomain-isolated passkeys (spec 229 P5): the ROOT passkey must be created/used at the
// person's OWN subdomain (RP ID = <label>.impact-agent.me). If we're not there yet, redirect;
// the subdomain auto-resumes via ?start / ?signin. Dev hosts (localhost/pages.dev) skip this.
function redirectForPasskey(intent: 'start' | 'signin', name: string): boolean {
  if (typeof window === 'undefined') return false;
  const label = nameLabel(name);
  if (!label) return false;
  const host = window.location.hostname;
  const onCentral = host === CENTRAL_AUTH_DOMAIN || host.endsWith('.' + CENTRAL_AUTH_DOMAIN);
  if (!onCentral) return false; // dev — RP is the dev host; no isolation hop
  if (host === `${label}.${CENTRAL_AUTH_DOMAIN}`) return false; // already home
  const u = new URL(personalAuthOrigin(label) + '/');
  u.searchParams.set(intent, label);
  window.location.href = u.toString();
  return true;
}

// Same subdomain isolation, but for the RELYING-APP enroll path ("Use my Impact name" inside a
// name-deferred enroll). The ROOT passkey ceremony must still run at the person's OWN subdomain
// (RP ID = <label>.impact-agent.me) — but unlike redirectForPasskey we must carry the FULL OIDC
// enroll request across the hop (so the grant can still be issued back to the relying app) and
// inject the now-chosen `agent_name` (the request arrived name-deferred/empty). The subdomain
// re-enters the SAME enroll, name-resolved, and creates/asserts the passkey at the correct RP ID.
function redirectForEnrollName(name: string): boolean {
  if (typeof window === 'undefined') return false;
  const label = nameLabel(name);
  if (!label) return false;
  const host = window.location.hostname;
  const onCentral = host === CENTRAL_AUTH_DOMAIN || host.endsWith('.' + CENTRAL_AUTH_DOMAIN);
  if (!onCentral) return false; // dev — RP is the dev host; no isolation hop
  if (host === `${label}.${CENTRAL_AUTH_DOMAIN}`) return false; // already home → resolve in place
  const u = new URL(personalAuthOrigin(label) + '/');
  u.search = window.location.search; // preserve the whole OIDC request (client_id, delegate, PKCE, state, mode…)
  u.searchParams.set('agent_name', toAgentName(label)); // resolve the name-deferred request to this name
  window.location.href = u.toString();
  return true;
}

function markEnrollChooserDone(enroll: { state?: string; codeChallenge?: string } | null | undefined) {
  if (!enroll) return;
  try {
    sessionStorage.setItem(`ap_chooser:${enroll.state || enroll.codeChallenge}`, '1');
  } catch {
    /* storage blocked */
  }
}

type View =
  | { k: 'checking' }
  | { k: 'blocked' }
  // `incomplete` = the requested name resolves to an SA that has no code on-chain
  // (orphan registry entry — historic relayer-paid /session/register-name from an
  // attempt whose deploy later failed). Surface this clearly instead of routing the
  // user into a flow that will revert with AA20 several steps later.
  | { k: 'incomplete'; name: string }
  | { k: 'credential' } // spec 257 W1 — the credential-first front door (default; name demoted)
  | { k: 'enroll-entry' } // spec 257 §11 — credential-first entry for a NAME-DEFERRED relying-app enroll
  | { k: 'enroll-recognized' } // already-authenticated member (ap_sso cookie) → one-tap authorize (ADR-0032)
  | { k: 'enroll-require-name'; agent: Address; token: string; via: Via }
  // First-connect provisioning declared by the relying app (`new_member`). Sits exactly where
  // 'enroll-require-name' sits — after the credential resolved a home, before the consent — because
  // both answer the same question: what does this app need to exist before it can be connected to.
  | { k: 'enroll-new-member'; agent: Address; token: string; via: Via; plan: NewMemberPlan }
  | { k: 'enroll-name'; reason?: 'passkey' | 'wallet' } // "Use my Impact name" within a name-deferred enroll → the named journey
  | { k: 'name'; reason?: 'passkey' | 'wallet' }
  | { k: 'journey'; variant: 'enroll-new' | 'self-serve'; name: string }
  | { k: 'enroll-existing'; name: string; agent: Address; via?: Via }
  | { k: 'org'; name: string; agent: Address }
  | { k: 'signin'; name: string };

export function EntryExperience({ mode }: { mode: 'entry' | 'enroll' }) {
  const api = useEnrollReq();
  const { openSession, session } = useSession();

  const [view, setView] = useState<View>(() => {
    if (mode === 'enroll') return { k: 'checking' };
    if (typeof window !== 'undefined') {
      const p = new URL(window.location.href).searchParams;
      const start = p.get('start');
      const signin = p.get('signin');
      if (start) return { k: 'journey', variant: 'self-serve', name: start };
      if (signin) return { k: 'signin', name: signin };
      // A per-handle home subdomain (<label>.impact-agent.me) IS that member's home — recognize
      // them from the host and go straight to "welcome back, sign in", pre-filled (not a generic
      // create screen). www/apex fall through to the name chooser.
      // spec 346 migration: the label may denote `<label>.me` or the legacy root — resolve the ordered candidates
      // (effect below) before showing "welcome back"; until then, the neutral busy view.
      const subLabel = parseAgentSubdomain(window.location.hostname);
      if (subLabel) return { k: 'checking' };
    }
    // spec 257 W1 — the www/apex self-serve default is CREDENTIAL-FIRST, not name-first. The name
    // is a public handle, not a login key; social/passkey resolve the home without it.
    return { k: 'credential' };
  });
  // Resolve the per-handle home subdomain to the ONE name its label denotes (typed-first candidates), then
  // show sign-in pre-filled. An unknown label still lands on sign-in with the name a NEW claim would take.
  useEffect(() => {
    if (mode !== 'entry' || typeof window === 'undefined') return;
    const subLabel = parseAgentSubdomain(window.location.hostname);
    if (!subLabel) return;
    let cancelled = false;
    void resolveHomeNameForLabel(subLabel).then((r) => {
      if (!cancelled) setView({ k: 'signin', name: r?.name ?? toAgentName(subLabel) });
    });
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mode]);
  // Curated entry first; a member-registered one once the hook has primed it. Both give the app
  // a NAME on the consent screen, which is the whole reason the person can tell who is asking.
  const clientCfg = api.enroll
    ? (whitelabel.relyingApps.find((a) => a.client_id === api.enroll!.aud) ??
       knownRelyingClient(api.enroll.aud) ??
       undefined)
    : undefined;
  const appHost = api.enroll
    ? (() => { try { return new URL(api.enroll!.redirectUri).host; } catch { return api.enroll!.redirectUri; } })()
    : '';
  const appName = api.enroll ? displayAppName(clientCfg?.name, appHost) : whitelabel.brand.name;
  const requiresNamedAgent = !!(api.enroll?.requireNamedAgent || clientCfg?.requireNamedAgent);
  // Which sign-in methods this relying app OFFERS. Absent = all of them, which is every client
  // that has not curated. Display only: nothing is disabled in the broker, and the returning-member
  // lane ignores this entirely so an existing home can always get back in the way it was made.
  const signInMethods = clientCfg?.signInMethods;

  // spec 321 — OTP continuation for relying-app enrolls: the email/phone cards open the session
  // INTERNALLY (they never call this component's onSession), so an enroll that reaches the
  // credential-first entry would otherwise stall signed-in with no grant. When a session appears
  // while we're on the enroll entry, re-enter the RECOGNIZED path — the one-tap authorize runs the
  // grant on the fresh home session and returns the code (same machinery the owner-op resume uses).
  useEffect(() => {
    if (mode !== 'enroll' || !api.enroll || !session) return;
    if (view.k !== 'enroll-entry' && view.k !== 'checking') return;
    void (async () => {
      markEnrollChooserDone(api.enroll);
      if (requiresNamedAgent) {
        const profile = await fetchProfile(session.token).catch(() => null);
        const addr = addressOf(profile?.agent);
        if (profile && addr && profile.deployed !== false && !profile.name) {
          setView({ k: 'enroll-require-name', agent: addr, token: session.token, via: resolveVia(profile.credential, session.via) });
          return;
        }
      }
      // First-connect provisioning, for the OTP families (email / phone) and anything else that
      // signs in on this front door: the cards open the session themselves, so this is the one
      // place the freshly-bootstrapped home is visible before the grant runs.
      //
      // GATED ON THE APP'S OWN DECLARATION AND NOTHING ELSE. An app with no `new_member` never gets
      // past the first line — no profile read, no agent-tree read, no screen — which is what makes
      // this byte-identical for every app in the registry but the one that opted in.
      const plan = newMemberPlan(clientCfg);
      if (!planIsEmpty(plan)) {
        const profile = await fetchProfile(session.token).catch(() => null);
        const addr = addressOf(profile?.agent);
        // `linkingCredential: false` — this front door only ever SIGNS IN. Adding a phone/email to
        // an existing account is the `status: 'linked'` branch inside the OTP cards, which returns
        // before any session is opened and never reaches an enroll view at all.
        if (profile && addr && isNewHomeMoment({ deployed: profile.deployed !== false, hasSession: true, linkingCredential: false })) {
          setView({ k: 'enroll-new-member', agent: addr, token: session.token, via: resolveVia(profile.credential, session.via), plan });
          return;
        }
      }
      setView({ k: 'enroll-recognized' });
    })();
  }, [mode, api.enroll, requiresNamedAgent, session, view.k, clientCfg]);

  // Enroll mode: resolve the requested name → new vs existing vs org-create.
  useEffect(() => {
    if (mode !== 'enroll' || !api.enroll) return;
    // Still resolving a member-registered client — decide nothing yet. Blocking here would
    // accuse a registered app of being untrusted for the length of one KV read.
    if (api.resolvingClient) return;
    if (!api.allowed) {
      setView({ k: 'blocked' });
      return;
    }
    // OIDC prompt=none — SILENT SSO (spec 230): the relying app asked for a no-UI outcome, so never
    // render the connect experience. No home session (no ap_sso cookie) → `login_required` (the app
    // clears its silent-SSO hint and shows its own Connect button). A recognized session → still
    // `interaction_required`: a silent grant here would mint a delegation without a consent gesture,
    // and this broker keeps no per-client remembered-consent store (yet) to justify skipping it.
    if (api.enroll.prompt === 'none') {
      api.deliverError(readSsoCookie() ? 'interaction_required' : 'login_required');
      return;
    }
    void (async () => {
      // OWNER-operation ceremonies (content-signer spec 266 / subscription-collect spec 272) run on the
      // owner's recognized HOME SESSION + the forwarded collectToken — they are NOT a named-home grant.
      // Route them to the recognized ceremony REGARDLESS of any `agent_name` the relying app sent (with no
      // cookie they fall to the entry and resume into the ceremony after sign-in, Step 3). This MUST come
      // before the name resolution below: otherwise an owner-op carrying an agent_name would route to
      // enroll-existing → OnboardingJourney, which has no owner-op branch and would silently run a
      // site-login grant (one signature → "permission granted" → bare ?code, nothing stored).
      if (isCeremonyTemplate(api.enroll!.template)) {
        setView({ k: readSsoCookie() ? 'enroll-recognized' : 'enroll-entry' });
        return;
      }
      // spec 257 §11: a name-deferred enroll arrives with an EMPTY `agent_name`. Show the
      // CREDENTIAL-FIRST entry (Continue with Google PRIMARY) — NOT the passkey-first journey
      // (whose "Get started" / empty-name "home" chip is wrong here). Google deploys a NAMELESS SA
      // (resumed post-redirect in GoogleEnrollResume); passkey/"use my name" fall to the named
      // journey (a new passkey home is subdomain-bound, so it needs a name). Don't call nameInfo('').
      if (!api.enroll!.name) {
        // Cookie / `#session=` → recognized (or wait while the handoff is consumed).
        // Do NOT re-run this when `session`/`phase` later updates — that remounts
        // RecognizedEnroll and restarts Gather/demo connect in a loop.
        if (hasSessionHandoff() || readSsoCookie()) {
          markEnrollChooserDone(api.enroll);
          setView({ k: readSsoCookie() ? 'enroll-recognized' : 'checking' });
          return;
        }
        setView({ k: 'enroll-entry' });
        return;
      }
      // A PINNED connect from an ALREADY-authenticated member one-taps: route to the recognized
      // ceremony, which ENFORCES the pin (session = pinned identity → straight to consent; a
      // different leftover session → cleared + credential chooser). Recognition was previously only
      // checked for NAMELESS enrolls, so pinned connects always fell through to name resolution —
      // which cannot one-tap (and for an EOA-ambiguous home showed the credential entry every time).
      // org-create keeps its dedicated named flow below.
      // THE HELPER, not the list: this pair and the one below are exactly the drift `isDeployTemplate`
      // was written to stop, and they had already fallen behind it.
      if (!isDeployTemplate(api.enroll!.template) && readSsoCookie()) {
        setView({ k: 'enroll-recognized' });
        return;
      }
      const info = await nameInfo(api.enroll!.name);
      // Orphan-registry guard: the name resolves to an SA but that SA has no
      // code on-chain. Refuse to use it — every downstream `executeCall` would
      // revert with AA20. Route to a dedicated 'incomplete' view that tells the
      // user to pick a different name. (Older `name-info` responses without the
      // `deployed` field fall through to legacy routing — undefined !== false.)
      if (info.exists && info.agent && info.deployed === false) {
        setView({ k: 'incomplete', name: api.enroll!.name });
        return;
      }
      if (isDeployTemplate(api.enroll!.template)) {
        // org-create assumes an existing member; resolve their person agent. Routed by TEMPLATE,
        // not `orgBase`: a chooser-mode request (spec 246 select-existing) carries NO org_base —
        // the member picks/creates the org HERE (OrgConsent's choose step).
        if (info.agent) setView({ k: 'org', name: api.enroll!.name, agent: info.agent });
        else setView({ k: 'blocked' });
        return;
      }
      // ROOT-passkey subdomain isolation (spec 229 P5): before running a person PASSKEY ceremony
      // (new bootstrap OR existing-home assertion), hop to <label>.impact-agent.me carrying the enroll
      // request, so the RP ID is the person's own home — not the www/apex host. No-op once we're already
      // on the subdomain (post-hop) and on dev hosts. org-create / incomplete returned above.
      // `needsPasskeyOrigin` keeps a wallet/social home OFF the hop: it gains nothing and would strand
      // the ceremony on a second front door at an origin the member never asked for.
      if (needsPasskeyOrigin(info) && redirectForEnrollName(api.enroll!.name)) return;
      if (info.exists && info.agent) {
        const via = viaForHome(info);
        // A social/KMS home reaching this path has NO recognized session (recognition would have
        // one-tapped) — the journey can't sign for it. Go straight through the provider sign-in with
        // the enroll stashed; GoogleEnrollResume completes the grant (incl. the x402 payment leg).
        if (via === 'google' || via === 'youversion') {
          api.postToOpener({ type: 'AC_PROGRESS', msg: 'Continuing with your provider…', idp: true });
          const stash = JSON.stringify({ enroll: api.enroll, popupMode: api.popupMode, name: api.enroll!.name ?? '' });
          if (via === 'youversion') continueWithYouVersion(undefined, stash); else continueWithGoogle(undefined, stash);
          return;
        }
        // AMBIGUOUS custody (EOA custodian, no passkey, NO published connection record): an EOA on-chain
        // may be a WALLET or the social/KMS C_sub — spec 280's own rule is "absence ⇒ show ALL credential
        // buttons", so route to the credential-first entry instead of guessing wallet (auto-MetaMask for
        // a Google home → "the active account isn't a custodian").
        if (via === 'wallet' && !info.connectionKind && !info.hasPasskey) { setView({ k: 'enroll-entry' }); return; }
        setView({ k: 'enroll-existing', name: api.enroll!.name, agent: info.agent, via });
      }
      else setView({ k: 'journey', variant: 'enroll-new', name: api.enroll!.name });
    })();
  }, [mode, api.enroll, api.allowed, api.resolvingClient]);

  if (view.k === 'checking') {
    return <Shell><div className="onboarding-busy"><span className="spinner spinner-lg" /><p className="onboarding-busy-msg">One moment…</p><WorkingBar /></div></Shell>;
  }
  if (view.k === 'blocked') {
    return (
      <Shell>
        <h1 className="onboarding-h1">Request blocked</h1>
        <p className="onboarding-sub">For your safety this request was blocked. Only start setup from a site you trust.</p>
      </Shell>
    );
  }
  if (view.k === 'incomplete') {
    return (
      <Shell>
        <h1 className="onboarding-h1">This name was set up partway, then stopped.</h1>
        <p className="onboarding-sub">
          The name <strong>{view.name}</strong> was reserved before, but its setup didn't finish, so it can't be used. Please pick a fresh name to start clean.
        </p>
        <button
          type="button"
          className="onboarding-primary"
          onClick={() => {
            if (typeof window !== 'undefined') {
              window.location.href = '/';
            }
          }}
        >
          Pick a different name
        </button>
      </Shell>
    );
  }
  if (view.k === 'journey') {
    return (
      <>
        <OnboardingJourney variant={view.variant} name={view.name} api={mode === 'enroll' ? api : undefined} />
        
      </>
    );
  }
  if (view.k === 'enroll-existing') {
    return <OnboardingJourney variant="enroll-existing" name={view.name} api={api} existingAgent={view.agent} initialVia={view.via} />;
  }
  if (view.k === 'org') {
    return <OrgConsent personAgent={view.agent} api={api} />;
  }
  if (view.k === 'signin') {
    return <SignInView name={view.name} onCreate={(n) => setView({ k: 'journey', variant: 'self-serve', name: nameLabel(n) })} onSession={async (t, via) => {
      await openSession(t, via, false);
      // Step 3 — signing in for an OWNER-OP ceremony establishes the home session; re-enter the
      // recognized path to run the ceremony (not a grant) on it.
      const t2 = api.enroll?.template;
      if (isCeremonyTemplate(t2)) setView({ k: 'enroll-recognized' });
    }} />;
  }
  // spec 257 W1 — credential-first front door (the self-serve default). Social/passkey resolve the
  // home with no name; "Use my Impact name" demotes to the name-first fallback.
  if (view.k === 'credential') {
    return (
      <CredentialFirstStart
        signInMethods={signInMethods}
        onUseName={(reason) => setView({ k: 'name', reason })}
        onSession={async (t, via) => { await openSession(t, via, false); }}
      />
    );
  }
  // spec 257 §11 — credential-first entry for a NAME-DEFERRED relying-app enroll. Same front door,
  // but `enrollApi` makes the Google button STASH the enroll so GoogleEnrollResume resumes the
  // grant + delivers the code back to the relying app (and deploys a nameless SA).
  if (view.k === 'enroll-recognized') {
    // Recognized returning member → authorize in one tap. Stale/absent session falls back to the entry.
    return <RecognizedEnroll api={api} onUnrecognized={() => setView({ k: 'enroll-entry' })} />;
  }
  if (view.k === 'enroll-entry') {
    return (
      <CredentialFirstStart
        enrollApi={api}
        appName={appName}
        signInMethods={signInMethods}
        onUseName={(reason) => setView({ k: 'enroll-name', reason })}
        onSession={async (t, via) => {
          await openSession(t, via, false);
          // Step 3 (spec: owner-op ceremony runs on the home session) — an OWNER-operation enroll
          // (content-signer / subscription-collect) reaches the entry only when there was no ap_sso
          // session. The member just signed in, so ap_sso now exists: re-enter the recognized path and
          // run the ceremony on this genuine home session (no relying-app-token credential reconstruction).
          const t2 = api.enroll?.template;
          if (isCeremonyTemplate(t2)) setView({ k: 'enroll-recognized' });
          // Spec 397 — a session opened ON the enroll screen (a demo person picked from the fold) continues as that
          // person on the recognized path: the app is authorized by them, prompt-free for a seeded demo person.
          else if (t2 === 'ask-as-me') setView({ k: 'enroll-recognized' });
        }}
      />
    );
  }
  if (view.k === 'enroll-require-name') {
    return (
      <RequiredNameGate
        agent={view.agent}
        token={view.token}
        via={view.via}
        appName={appName}
        onClaimed={() => setView({ k: 'enroll-recognized' })}
      />
    );
  }
  if (view.k === 'enroll-new-member') {
    // `onDone` fires on success, on skip, and immediately when the member already has everything —
    // so this can only ever DELAY the recognized path, never replace it.
    return (
      <NewMemberSetup
        person={view.agent}
        token={view.token}
        via={view.via}
        appName={appName}
        plan={view.plan}
        onDone={() => setView({ k: 'enroll-recognized' })}
      />
    );
  }
  // "Use my Impact name" within a name-deferred enroll → collect a name, then route to the named
  // enroll path (existing home → sign in + grant; new → the named journey which handles passkey).
  if (view.k === 'enroll-name') {
    const reason = view.reason; // set when the member explicitly chose the device-credential lane
    return <NameStart enrollApi={api} reason={reason} onStart={async (name) => {
      // OWNER-ops never take the named grant path (no owner-op branch in OnboardingJourney). Sign in to
      // the named home, then resume the recognized ceremony on that session (Step 3 — SignInView onSession).
      if (isCeremonyTemplate(api.enroll?.template)) {
        setView({ k: 'signin', name }); return;
      }
      // Resolve the name BEFORE deciding to hop: only a PASSKEY ceremony needs the person's own RP ID
      // (spec 229 P5). Resolving first is what lets `needsPasskeyOrigin` keep a wallet/social home on
      // the apex — the hop used to be unconditional, so every named home took a pointless origin jump.
      const info = await nameInfo(name);
      if (info.exists && info.agent && info.deployed === false) { setView({ k: 'incomplete', name }); return; }
      // ROOT-passkey subdomain isolation: hop to <label>.impact-agent.me carrying the enroll request, so
      // the passkey is created/asserted at the person's own RP ID. On dev hosts / when already home this
      // is a no-op and we resolve in place below.
      if (needsPasskeyOrigin(info) && redirectForEnrollName(name)) return;
      if (info.exists && info.agent) {
        const via = viaForHome(info);
        // Social/KMS home on the name path = no recognized session → provider sign-in with the
        // enroll stashed (GoogleEnrollResume finishes the grant incl. the payment leg).
        if (via === 'google' || via === 'youversion') {
          api.postToOpener({ type: 'AC_PROGRESS', msg: 'Continuing with your provider…', idp: true });
          const stash = JSON.stringify({ enroll: api.enroll, popupMode: api.popupMode, name: toAgentName(nameLabel(name)) });
          if (via === 'youversion') continueWithYouVersion(undefined, stash); else continueWithGoogle(undefined, stash);
          return;
        }
        // Ambiguous custody (EOA-only, no published connection record) → all credential buttons (spec 280)
        // — but ONLY when the member has not already told us. `reason` is set precisely when they got here
        // by pressing "Continue with a passkey or wallet", i.e. they chose the DEVICE-credential lane; the
        // home has no passkey on-chain, so the wallet is the only device credential it can assert with.
        // Bouncing them back to the chooser they just left is a closed cycle: enroll-entry's only
        // device-credential button routes straight back to this name door (the enroll front door has no
        // wallet button by design, spec 259 / ADR-0029), so a named wallet home could never connect.
        if (!reason && via === 'wallet' && !info.connectionKind && !info.hasPasskey) { setView({ k: 'enroll-entry' }); return; }
        setView({ k: 'enroll-existing', name, agent: info.agent, via });
      }
      else setView({ k: 'journey', variant: 'enroll-new', name });
    }} />;
  }
  // Name-first fallback (reached via "Use my Impact name").
  return <NameStart reason={view.k === 'name' ? view.reason : undefined} onStart={(name, exists) => {
    if (exists) {
      if (!redirectForPasskey('signin', name)) setView({ k: 'signin', name });
    } else {
      if (!redirectForPasskey('start', name)) setView({ k: 'journey', variant: 'self-serve', name });
    }
  }} />;
}

function Shell({ children, compact }: { children: React.ReactNode; compact?: boolean }) {
  // A client that asked not to name the substrate (`consent.hideSubstrate`) doesn't, on its own sign-in
  // card. Read off THIS page's authorize URL only — never the sessionStorage stash, which can outlive the
  // request and would hide the line on a later, unrelated visit. This tree is client-only (ssr:false).
  const [hideSubstrate] = useState(() => {
    if (typeof window === 'undefined') return false;
    const aud = parseEnrollReq()?.aud;
    return knownRelyingClient(aud)?.consent?.hideSubstrate === true;
  });
  return (
    <div className="onboarding-screen">
      <div className={compact ? 'onboarding-card enroll-compact' : 'onboarding-card'}>{children}</div>
      <HomeFooter compact hideSubstrate={hideSubstrate} />
    </div>
  );
}

/** Selected state for the email/phone method toggles — the open card's button reads as CHOSEN
 *  (UX report 2026-07-10: clicking "Continue with phone" revealed the card but nothing marked the
 *  option selected). Opening one method closes the other (mutually exclusive). */
const SELECTED_METHOD_STY: React.CSSProperties = { background: 'var(--color-surface-sunken)', borderColor: 'var(--color-text-faint)' };

// Yield one frame so a just-set busy state actually PAINTS before a blocking credential call. Wallet
// (`window.ethereum.request`) and passkey (`navigator.credentials.get`) trigger a native prompt
// within the click task's synchronous prefix — without this yield React commits the busy UI but the
// browser never repaints it first, so the click looks dead until MetaMask/the passkey dialog appears.
const paintYield = (): Promise<void> =>
  new Promise<void>((resolve) => {
    if (typeof requestAnimationFrame === 'function') requestAnimationFrame(() => resolve());
    else setTimeout(resolve, 0);
  });

// ── Self-serve: choose your name in the community ─────────────────────────────
// `enrollApi` (relying-app enroll only): the "Continue with Google" button must STASH the enroll so
// the post-redirect GoogleEnrollResume finishes the grant + delivers the code back to the app.
// The name screen does TWO jobs — sign in to an EXISTING home, or create a NEW one — so it stays
// NEUTRAL ("Find your home") until `nameInfo()` resolves whether the typed name exists, then commits to
// "Continue to <name>" (taken → sign in) or "Create <name>" (available). No "join" before the system
// confirms availability. `reason` (passkey/wallet) explains WHY we routed here from a credential click.
function NameStart({ onStart, enrollApi, reason }: { onStart: (name: string, exists: boolean) => void; enrollApi?: EnrollApi; reason?: 'passkey' | 'wallet' }) {
  const [value, setValue] = useState('');
  const [avail, setAvail] = useState<'idle' | 'checking' | 'available' | 'taken'>('idle');
  const [busy, setBusy] = useState(false);
  const label = nameLabel(value);
  const brand = whitelabel.brand.name;
  const fullName = label ? toAgentName(label) : '';                 // <label>.impact (the public handle)
  const homeHost = label ? `${label}.${CENTRAL_AUTH_DOMAIN}` : '';  // <label>.impact-agent.me (the home)
  const onGoogle = () => {
    const stash = enrollApi?.enroll
      ? JSON.stringify({ enroll: enrollApi.enroll, popupMode: enrollApi.popupMode, name: label ? toAgentName(label) : '' })
      : undefined;
    // Heading to Google — warn a popup opener (COOP severs it) so it waits for the relay, not close.
    enrollApi?.postToOpener({ type: 'AC_PROGRESS', msg: 'Continuing with Google…', idp: true });
    continueWithGoogle(label ? toAgentName(label) : undefined, stash);
  };
  const onYouVersion = () => {
    const stash = enrollApi?.enroll
      ? JSON.stringify({ enroll: enrollApi.enroll, popupMode: enrollApi.popupMode, name: label ? toAgentName(label) : '' })
      : undefined;
    enrollApi?.postToOpener({ type: 'AC_PROGRESS', msg: 'Continuing with YouVersion…', idp: true });
    continueWithYouVersion(label ? toAgentName(label) : undefined, stash);
  };

  useEffect(() => {
    if (!label) { setAvail('idle'); return; }
    setAvail('checking');
    const t = setTimeout(async () => {
      const info = await nameInfo(toAgentName(label));
      setAvail(info.exists ? 'taken' : 'available');
    }, 400);
    return () => clearTimeout(t);
  }, [label]);

  // CTA commits ONLY once the name is resolved: neutral "Continue" while idle/checking, then the
  // sign-in vs create verb once we know if it exists.
  const cta = busy ? 'One moment…'
    : avail === 'checking' ? 'Checking…'
    : avail === 'taken' ? `Continue to ${fullName}`
    : avail === 'available' ? `Create ${fullName}`
    : 'Continue';

  return (
    <Shell>
      <BrandShield size={56} />
      <h1 className="onboarding-h1">Find your {brand} home</h1>
      <p className="onboarding-sub">
        Use your {brand} name if you know it. Your name is your public handle; Google, passkeys, and
        wallets are how you prove it&apos;s yours.
      </p>
      {reason && (
        <p className="onboarding-note">
          {reason === 'passkey'
            ? `Passkeys are tied to your ${brand} home address. Enter your ${brand} name so we can open the right home.`
            : `We need your ${brand} name to open the right home for this wallet.`}
        </p>
      )}
      <input
        className="onboarding-input"
        value={value}
        onChange={(e) => setValue(e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, ''))}
        placeholder="e.g. alice"
        aria-label={`Your ${brand} name`}
        autoCapitalize="none"
        spellCheck={false}
      />
      {label && (
        <div className="onboarding-name-preview">
          {fullName} <span className="onboarding-name-host">· home at {homeHost}</span>
        </div>
      )}
      {avail === 'taken' && (
        <p className="onboarding-hint taken">That name already exists. Sign in if it&apos;s yours, or choose another name.</p>
      )}
      {avail === 'available' && <p className="onboarding-hint ok">✓ {fullName} is available</p>}
      <button
        className="btn-primary"
        disabled={!label || busy || avail === 'checking'}
        onClick={() => { setBusy(true); onStart(toAgentName(label), avail === 'taken'); }}
      >
        {cta}
      </button>
      {(googleEnabled || youversionEnabled) && (
        <>
          <div className="method-or">Other ways to continue</div>
          <SocialConnect onGoogle={onGoogle} onYouVersion={onYouVersion} />
        </>
      )}
    </Shell>
  );
}

// ── spec 257 W1: credential-first front door ──────────────────────────────────
// Social entry: a DIRECT "Continue with Google" (and "Continue with YouVersion" when that provider is
// configured) — one button per provider, never a "Continue with Social" picker that hides the choice
// behind a click. Used on the credential-first + name-entry surfaces where the USER picks a provider —
// NOT SignInView, where the home's own connectionKind already dictates which social button to show.
function SocialConnect({ onGoogle, onYouVersion, primary }: { onGoogle: () => void; onYouVersion: () => void; primary?: boolean }) {
  if (!googleEnabled && !youversionEnabled) return null;
  const cls = primary ? 'btn-primary' : 'btn-ghost onboarding-secondary';
  return (
    <>
      {googleEnabled && <button className={cls} onClick={onGoogle}>Continue with Google</button>}
      {youversionEnabled && <button className={googleEnabled ? 'btn-ghost onboarding-secondary' : cls} onClick={onYouVersion}>Continue with YouVersion</button>}
    </>
  );
}

// Social/passkey is the way in; the Impact name is a public handle, not a login key. Google
// resolves the home server-side with NO name (spec 235); passkeys are subdomain-isolated (RP =
// <label>.impact-agent.me) so a discoverable assertion here only succeeds for a home reachable
// from this origin — otherwise we route to the name path (which hops to the right subdomain).
function CredentialFirstStart({ onUseName, onSession, enrollApi, appName, signInMethods }: {
  /** Absent = offer everything (the default for every client that has not curated). */
  signInMethods?: readonly ('social' | 'email' | 'phone' | 'passkey' | 'name')[];
  onUseName: (reason?: 'passkey' | 'wallet') => void;
  onSession: (token: string, via: string) => Promise<void>;
  // spec 257 §11 — when set, this is a NAME-DEFERRED relying-app enroll: Google stashes the enroll
  // (resumed in GoogleEnrollResume → nameless SA + grant), and passkey routes to the name path
  // (a new passkey home is subdomain-bound, so it needs a name) rather than a discoverable login.
  enrollApi?: EnrollApi;
  appName?: string;
}) {
  // What the email card says while it makes a new home — the client's own words when it has them
  // (Gather27: "Signing you in…"), the shared `copy.portalStepBusy` otherwise.
  const emailBusyNote = clientCopy(enrollApi?.enroll ? knownRelyingClient(enrollApi.enroll.aud) : undefined, 'portalStepBusy');
  const [busy, setBusy] = useState<'passkey' | 'wallet' | null>(null);
  const [err, setErr] = useState('');
  // Email / phone sign-in / bootstrap: reveal an inline EmailAuthCard / PhoneAuthCard. Both call the SAME
  // useSession().openSession this front door is mounted under (portal Gate), so a verified/bootstrapped
  // email or phone lands in the portal.
  const [showEmail, setShowEmail] = useState(false);
  const [showPhone, setShowPhone] = useState(false);
  // The wallet button is offered whenever the config names it; whether an injected provider is actually
  // present is a client-only check (set after mount to avoid an SSR/first-paint mismatch) that decides
  // what the CLICK does — the door never hides a configured way in because this browser lacks it.
  const [walletAvail, setWalletAvail] = useState(false);
  useEffect(() => { setWalletAvail(hasWallet()); }, []);
  // Remote-persona arrival (uupg tracker demo — ?signer=remote&opener=<allowlisted>): the opener holds the
  // persona's key and signs over postMessage, so auto-run the REAL wallet ceremony — the SIWE message +
  // any deploy userOpHash route to the opener via wallet.ts provider(). One-shot per mount.
  const remoteStarted = useRef(false);
  useEffect(() => {
    if (remoteStarted.current || !initRemoteSigner()) return;
    remoteStarted.current = true;
    void withWallet();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  const onGoogle = () => {
    const stash = enrollApi?.enroll
      ? JSON.stringify({ enroll: enrollApi.enroll, popupMode: enrollApi.popupMode, name: '' })
      : undefined;
    // Tell a popup opener we're leaving for Google BEFORE we navigate (COOP will sever the opener):
    // it must stop trusting `popup.closed` and wait for the relay channel instead. No-op otherwise.
    enrollApi?.postToOpener({ type: 'AC_PROGRESS', msg: 'Continuing with Google…', idp: true });
    continueWithGoogle(undefined, stash);
  };
  const onYouVersion = () => {
    const stash = enrollApi?.enroll
      ? JSON.stringify({ enroll: enrollApi.enroll, popupMode: enrollApi.popupMode, name: '' })
      : undefined;
    enrollApi?.postToOpener({ type: 'AC_PROGRESS', msg: 'Continuing with YouVersion…', idp: true });
    continueWithYouVersion(undefined, stash);
  };
  // spec 257 W3 — when a passkey resolves an EXISTING home, show the "We found your Impact home"
  // confirmation beat before issuing the session (display only; the token is already minted).
  const [resolved, setResolved] = useState<{ token: string; name: string | null; address: Address | null; via: string; fresh?: boolean } | null>(null);
  const [busyStep, setBusyStep] = useState('');

  async function withPasskey() {
    setBusy('passkey');
    setErr('');
    await paintYield(); // paint "Checking your device…" before the passkey dialog blocks
    try {
      // registerIfMissing=false: never silently mint a key here — a fresh user takes the named/
      // bootstrap path. A discoverable assertion that resolves an existing home → straight in.
      const out = await passkeyLogin(false);
      if (out.status === 'issued' && out.token) {
        // Best-effort handle for the beat — never gates the session: on any failure we fall
        // straight through to onSession with what (if anything) we have.
        let name: string | null = null;
        let address: Address | null = null;
        try {
          const p = await fetchProfile(out.token);
          name = p?.name ?? null;
          address = p?.agent ? ((p.agent.split(':').pop() ?? null) as Address | null) : null;
        } catch { /* show the beat without a handle */ }
        setResolved({ token: out.token, name, address, via: 'passkey' });
        return;
      }
      // No discoverable home at this origin (subdomain isolation / new user) → name path.
      onUseName('passkey');
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'passkey sign-in failed');
    } finally {
      setBusy(null);
    }
  }

  // Wallet (SIWE/EOA) — parallel to passkey. Connect the wallet + sign SIWE: an EXISTING
  // wallet-custodied home resolves straight in (the beat → session); a NEW wallet (no home yet)
  // takes the name path, where the journey deploys a named wallet home. Wallet is NOT
  // subdomain-bound, so no origin hop is needed (unlike passkey).
  async function withWallet() {
    setBusy('wallet');
    setBusyStep('');
    setErr('');
    await paintYield(); // paint "Confirm in your wallet…" before MetaMask blocks
    try {
      const out = await siweLogin();
      if (out.status === 'issued' && out.token) {
        let name: string | null = null;
        let address: Address | null = (out.agent ?? null) as Address | null;
        try {
          const p = await fetchProfile(out.token);
          name = p?.name ?? null;
          if (p?.agent) address = (p.agent.split(':').pop() ?? address) as Address | null;
        } catch { /* show the beat without a handle */ }
        setResolved({ token: out.token, name, address, via: 'wallet' });
        return;
      }
      if (out.status === 'bootstrap') {
        // New wallet — no home for this EOA yet. Secure a NAMELESS home right here (one wallet prompt for the
        // deploy, one SIWE for the session) — never a detour through choosing a name; the public name is a
        // later choice from the portal, exactly as a Google home is born (spec 257 name-deferral).
        setBusyStep('Preparing your home…');
        const made = await secureHomeWalletNoName(setBusyStep);
        if (!made.ok) { setErr(made.error); return; }
        setResolved({ token: made.token, name: null, address: made.home.address, via: 'wallet', fresh: made.fresh });
        return;
      }
      setErr(('reason' in out && out.reason) || 'wallet sign-in failed');
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'wallet sign-in failed');
    } finally {
      setBusy(null);
    }
  }

  // Resolved-home confirmation beat (greenfield 10): "Welcome back" + handle + role/org chips,
  // then auto-advance into the session. A returning passkey member is never `fresh`.
  if (resolved) {
    return (
      <HomeResolvedView
        fresh={resolved.fresh === true}
        knownName={resolved.name}
        address={resolved.address}
        token={resolved.token}
        onContinue={() => { void onSession(resolved.token, resolved.via); }}
      />
    );
  }

  const enroll = Boolean(enrollApi);
  // Curation applies to the ENROLL screen only — the one a relying app sends people to. The
  // self-serve lane below has no app asking on anyone's behalf, so it keeps every method, and
  // `SocialConnect` is shared by both branches which is why this guard is on `enrollApi` rather
  // than on the list alone. An absent list offers everything, as every uncurated client does.
  const curated = enrollApi ? signInMethods : undefined;
  const offers = (m: 'social' | 'email' | 'phone' | 'passkey' | 'name') => !curated || curated.includes(m);
  // Exactly one method, and it is email: skip the reveal button and show the field itself.
  const soleMethod = curated?.length === 1 && curated[0] === 'email';
  return (
    <Shell compact={enroll}>
      <BrandShield size={enroll ? 40 : 56} />
      <h1 className="onboarding-h1">{enroll && appName ? `Continue to ${appName}` : whitelabel.copy.arrivalTitle}</h1>
      <p className="onboarding-sub">
        {enroll
          ? whitelabel.copy.enrollSub
          : `Sign in or get started. Your ${whitelabel.brand.name} name is how others find your agent — not something you need to remember to get back in.`}
      </p>
      {offers('social') && <SocialConnect onGoogle={onGoogle} onYouVersion={onYouVersion} primary />}
      {enrollApi ? (
        <>
          {/* When a client offers email ALONE there is nothing to choose between, so the card is
              open and the person types straight into it rather than pressing a button that only
              reveals the one field they were always going to use. */}
          {offers('email') && emailEnabled && !soleMethod && (
            <button
              className="btn-ghost onboarding-secondary"
              style={showEmail ? SELECTED_METHOD_STY : undefined}
              aria-pressed={showEmail}
              onClick={() => { setShowEmail((v) => !v); setShowPhone(false); }}
              disabled={busy !== null}
            >
              Continue with email
            </button>
          )}
          {offers('email') && emailEnabled && (showEmail || soleMethod) && (
            <div style={{ margin: '.4rem 0 .2rem' }}>
              <EmailAuthCard busyNote={emailBusyNote} />
            </div>
          )}
          {offers('phone') && phoneEnabled && (
            <>
              <button
                className="btn-ghost onboarding-secondary"
                style={showPhone ? SELECTED_METHOD_STY : undefined}
                aria-pressed={showPhone}
                onClick={() => { setShowPhone((v) => !v); setShowEmail(false); }}
                disabled={busy !== null}
              >
                Continue with phone
              </button>
              {showPhone && (
                <div style={{ margin: '.4rem 0 .2rem' }}>
                  <PhoneAuthCard />
                </div>
              )}
            </>
          )}
          {offers('passkey') && passkeyEnabled && (
            // A passkey home is subdomain-bound, so the name path opens the right home.
            <button className="btn-ghost onboarding-secondary" onClick={() => onUseName('passkey')}>
              Continue with a passkey
            </button>
          )}
          {offers('passkey') && walletEnabled && (
            // The wallet is not subdomain-bound: an existing EOA home signs straight in, a new EOA gets a
            // NAMELESS home here — then the beat hands the session to the enroll flow. Never the name path.
            <button
              className="btn-ghost onboarding-secondary"
              onClick={() => { if (walletAvail) void withWallet(); else setErr('No wallet found in this browser — install a wallet extension such as MetaMask, or continue another way.'); }}
              disabled={busy !== null}
            >
              {busy === 'wallet' ? (busyStep || 'Confirm in your wallet…') : 'Continue with a wallet'}
            </button>
          )}
        </>
      ) : (
        <>
          {/* Self-serve, in the configured order: Google above, then email, then the wallet — a discoverable
              passkey / existing wallet home resolves straight in; a brand-new credential falls through to the
              name path. Passkey and phone appear only when the white-label config offers them. */}
          {passkeyEnabled && (
            <button
              className={googleEnabled ? 'btn-ghost onboarding-secondary' : 'btn-primary'}
              onClick={withPasskey}
              disabled={busy !== null}
            >
              {busy === 'passkey' ? 'Checking your device…' : 'Continue with a passkey'}
            </button>
          )}
          {emailEnabled && (
            <button
              className="btn-ghost onboarding-secondary"
              style={showEmail ? SELECTED_METHOD_STY : undefined}
              aria-pressed={showEmail}
              onClick={() => { setShowEmail((v) => !v); setShowPhone(false); }}
              disabled={busy !== null}
            >
              Continue with email
            </button>
          )}
          {emailEnabled && showEmail && (
            // Verify a code (existing email home) OR bootstrap a KMS-custodied home (no home yet) — both
            // open the session via useSession, so the Gate advances into the portal. No device gesture.
            <div style={{ margin: '.4rem 0 .2rem' }}><EmailAuthCard /></div>
          )}
          {walletEnabled && (
            <button
              className="btn-ghost onboarding-secondary"
              onClick={() => { if (walletAvail) void withWallet(); else setErr('No wallet found in this browser — install a wallet extension such as MetaMask, or continue another way.'); }}
              disabled={busy !== null}
            >
              {busy === 'wallet' ? (busyStep || 'Confirm in your wallet…') : 'Continue with a wallet'}
            </button>
          )}
          {phoneEnabled && (
            <button
              className="btn-ghost onboarding-secondary"
              style={showPhone ? SELECTED_METHOD_STY : undefined}
              aria-pressed={showPhone}
              onClick={() => { setShowPhone((v) => !v); setShowEmail(false); }}
              disabled={busy !== null}
            >
              Continue with phone
            </button>
          )}
          {phoneEnabled && showPhone && (
            // Verify an SMS code (existing phone home) OR bootstrap a KMS-custodied home (no home yet). Same
            // session/Gate advance as email; add a passkey afterward for the durable credential (spec 320).
            <div style={{ margin: '.4rem 0 .2rem' }}><PhoneAuthCard /></div>
          )}
        </>
      )}
      {err && <p className="onboarding-hint taken">{err}</p>}
    {/* Spec 397 — on an enroll screen the fold hands the persona's session to the enroll flow (recognized path next). */}
    {enroll ? <DemoPeopleFold enroll appName={appName} onSession={onSession} /> : <DemoPeopleFold />}
      </Shell>
  );
}

// ── Returning member sign-in ──────────────────────────────────────────────────
function SignInView({ name, onSession, onCreate }: { name: string; onSession: (token: string, via: string) => Promise<void>; onCreate?: (name: string) => void }) {
  const [busy, setBusy] = useState(false);
  const [busyMsg, setBusyMsg] = useState('Confirming…');
  const [err, setErr] = useState('');
  const [info, setInfo] = useState<NameInfo | null>(null);
  // An email/phone-custodied home signs in via the code, not a device credential — its KMS custodian looks
  // like an EOA on-chain (→ a misleading "Continue with wallet"). Always offer email + phone here so those
  // homes can get in; the cards resolve the home via the email/phone facet + open the session.
  const [showEmail, setShowEmail] = useState(false);
  const [showPhone, setShowPhone] = useState(false);
  // Recognize an existing cross-subdomain `ap_sso` session that resolves to THIS home → offer a one-tap
  // "Continue as <name>" without a fresh credential assertion (mirrors the relying-app RecognizedEnroll
  // path). Fixes the dead-end where a direct visit to a passkey-only home on a device WITHOUT the passkey
  // forced "Continue with passkey" and failed, even though the member was already signed in. `null` =
  // not recognized → fall through to credential sign-in; set → show the one-tap continue.
  const [recognized, setRecognized] = useState<{ token: string; via: string } | null>(null);
  useEffect(() => {
    let cancelled = false;
    void (async () => {
      const ni = await nameInfo(name).catch(() => ({}) as NameInfo);
      if (cancelled) return;
      setInfo(ni);
      const sso = readSsoCookie();
      if (!sso?.token || !ni.agent) return;
      const profile = await fetchProfile(sso.token).catch(() => null);
      const addr = addressOf(profile?.agent);
      // Only recognize when the live session resolves to THIS exact home (a different signed-in home,
      // or a stale/undeployed one, falls through to credential sign-in — one mechanism, ADR-0013).
      if (!cancelled && addr && profile?.deployed !== false && addr.toLowerCase() === ni.agent.toLowerCase()) {
        setRecognized({ token: sso.token, via: sso.via || 'sso' });
      }
    })();
    return () => { cancelled = true; };
  }, [name]);

  async function go(via: 'passkey' | 'wallet', passkeyMode: 'local' | 'discoverable' = 'local') {
    if (via === 'passkey' && redirectForPasskey('signin', name)) return;
    setBusyMsg(via === 'wallet' ? 'Connect your wallet…' : 'Checking your passkey…');
    setBusy(true);
    setErr('');
    await paintYield(); // show the busy state BEFORE MetaMask / the passkey dialog blocks
    try {
      const out = await openHome(name, via, { passkeyMode });
      if (out.ok) await onSession(out.token, via);
      else setErr(out.error);
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'sign-in failed');
    } finally {
      setBusy(false);
    }
  }

  // Show the credentials this home ACTUALLY has (until name-info loads, show passkey+wallet).
  // Google stays available (a Google-custodied home re-derives via Google).
  // A chain with no P-256 verifier (no RIP-7212 precompile at 0x100, no wired Solidity fallback) cannot
  // verify ANY passkey: `staticcall` to an empty address succeeds with no returndata, so every assertion
  // comes back "invalid" rather than reverting. An account there can HOLD registered passkeys — adding
  // one is authorized by an existing ECDSA custodian — while none of them can ever sign. Offering the
  // button anyway sent members round the ceremony repeatedly to be told their passkey "is not a
  // custodian" (faithnet, 2026-09-01). `undefined`/`null` means the probe could not answer, and an
  // unknown answer must not hide a method that may work.
  const passkeyUnverifiable = info?.passkeySigningAvailable === false;
  const showPasskey = info ? !!info.hasPasskey && !passkeyUnverifiable : true;
  const showWallet = info ? !!info.hasEoa : true;
  const onlyWallet = info ? !!info.hasEoa && !info.hasPasskey : false;
  const notFound = info ? info.exists === false : false;
  // A SOCIAL (OIDC) custodian — YouVersion / Google — signs via the KMS path, NOT a user wallet. Its
  // custodian address is KMS-derived and LOOKS like an EOA (so hasEoa=true), which would otherwise make a
  // youversion/google home wrongly offer "Continue with wallet". The connection-bootstrap kind (spec 280)
  // is the authoritative signer signal, so it drives the CTA.
  // email/phone (specs 319/320) join google/youversion as social/KMS custodians — their published
  // connectionKind drives the CTA AND suppresses the misleading wallet button (their C_sub looks like an EOA).
  const socialKind: 'google' | 'youversion' | 'email' | 'phone' | null =
    info?.connectionKind === 'google' || info?.connectionKind === 'youversion' ||
    info?.connectionKind === 'email' || info?.connectionKind === 'phone' ? info.connectionKind : null;
  // Which social buttons the door shows — the published kind's own as primary, else (kind unpublished, EOA
  // custodian, no passkey) the deployment's open social ways in as a secondary fallback: `named-home-door.ts`.
  // Wallet stays offered on the fallback (it may genuinely be an EOA home).
  const socialButtons = info ? socialButtonsForNamedHome({ connectionKind: info.connectionKind, hasEoa: info.hasEoa, hasPasskey: info.hasPasskey, methods: whitelabel.onboarding.credentialMethods }) : [];
  // PASSKEY-FIRST DEVICE: this browser holds a local passkey for this host AND the home has a
  // passkey custodian on-chain → the passkey is the fastest way in (the member enrolled it — via
  // the email-card offer or elsewhere — precisely so return visits skip the code/OIDC hop). Make
  // "Continue with passkey" the primary CTA even for an email/phone/social-custodied home, and
  // don't auto-open the code card over it. Email/phone stay right below as the fallback: when the
  // passkey breaks, the code signs them in and the email card offers a fresh passkey.
  const [localPk, setLocalPk] = useState(false);
  useEffect(() => {
    try { setLocalPk(!!loadPasskey()); } catch { /* storage blocked */ }
  }, []);
  const passkeyFirst = localPk && (info ? !!info.hasPasskey : false);
  // When the home publishes email/phone, auto-open the matching code card so it's the primary path
  // — unless this device is passkey-first (see above).
  useEffect(() => {
    try { if (loadPasskey()) return; } catch { /* storage blocked */ }
    if (info?.connectionKind === 'email') setShowEmail(true);
    if (info?.connectionKind === 'phone') setShowPhone(true);
  }, [info?.connectionKind]);
  // LOCAL pre-select: this browser remembers how it last opened this home (set at every session
  // open), so a returning phone/email member lands with their code card ALREADY open instead of
  // re-picking the method. Private convenience only — the PUBLIC signal stays the opt-in spec-280
  // connection record above; neither overrides the other, they both just open a card.
  useEffect(() => {
    try {
      if (loadPasskey()) return; // passkey-first device — don't open the code card over the passkey CTA
      const last = localStorage.getItem(`ap-last-via:${nameLabel(name)}`);
      if (last === 'email') setShowEmail(true);
      if (last === 'phone') setShowPhone(true);
    } catch { /* storage blocked */ }
  }, [name]);
  // Arriving at a NOT-YET-EXISTING name's subdomain and signing in with an OTP card can resolve an
  // EXISTING NAMELESS home (the phone/email facet already points somewhere) — the member came here
  // wanting to BE this name, so claim it for that home (KMS-signed, zero prompts, once). A home that
  // already HAS a name is untouched — this only completes the nameless case (rich-phone3).
  const { session: liveSession, profile: liveProfile, refreshProfile } = useSession();
  const claimRef = useRef(false);
  const notFoundNow = info ? info.exists === false : false;
  useEffect(() => {
    if (claimRef.current || !notFoundNow || !liveSession || !liveProfile) return;
    const addr = addressOf(liveProfile.agent);
    if (!addr || liveProfile.deployed === false || liveProfile.name) return;
    claimRef.current = true;
    void (async () => {
      try {
        const via = resolveVia(liveProfile.credential, liveSession.via);
        const sign = await signHashFor(via, addr, { token: liveSession.token });
        const res = await claimName(addr, sign, nameLabel(name));
        if (res.ok) await refreshProfile();
        else console.warn('[signin] name claim failed (claim it from the Naming page):', res.error);
      } catch (e) {
        console.warn('[signin] name claim failed (claim it from the Naming page):', e);
      }
    })();
  }, [notFoundNow, liveSession, liveProfile, name, refreshProfile]);

  // Recognized: the member already has a live session for THIS home → one tap, no fresh credential.
  if (recognized) {
    return (
      <Shell>
        <BrandShield size={56} />
        <h1 className="onboarding-h1">Welcome back</h1>
        <p className="onboarding-sub">You&apos;re already signed in — continue as <strong>{nameLabel(name)}</strong>.</p>
        {busy ? (
          <div className="onboarding-busy"><span className="spinner spinner-lg" /><p className="onboarding-busy-msg">Confirming…</p><WorkingBar /></div>
        ) : (
          <>
            <button
              className="btn-primary"
              onClick={async () => {
                setBusyMsg('Signing you in…');
                setBusy(true);
                setErr('');
                try {
                  await onSession(recognized.token, recognized.via);
                } catch (e) {
                  setErr(e instanceof Error ? e.message : 'sign-in failed');
                  setBusy(false);
                }
              }}
            >
              Continue as {nameLabel(name)}
            </button>
            <button className="btn-ghost onboarding-secondary" onClick={() => setRecognized(null)}>
              Sign in a different way
            </button>
          </>
        )}
        {err && <p className="onboarding-hint taken">{err}</p>}
      </Shell>
    );
  }

  return (
    <Shell>
      <BrandShield size={56} />
      <h1 className="onboarding-h1">Welcome back</h1>
      <p className="onboarding-sub">Sign in to <strong>{name}</strong> — your home in the {whitelabel.brand.community}.</p>
      {busy || !info ? (
        // Wait for name-info before rendering credential buttons. Otherwise the pre-load defaults
        // (showPasskey=true) flash "Continue with passkey" as the primary even for a WALLET-only home,
        // so the member is taken to passkey when they should get wallet. Show only this home's ACTUAL
        // credential(s) once resolved.
        <div className="onboarding-busy"><span className="spinner spinner-lg" /><p className="onboarding-busy-msg">{busy ? busyMsg : 'Opening your home…'}</p><WorkingBar /></div>
      ) : notFound ? (
        <>
          <p className="onboarding-hint taken">No home named <strong>{nameLabel(name)}</strong> yet.</p>
          {/* Route into the FULL creation journey (passkey / wallet / social / email / phone), which
              claims THIS name with whichever credential is chosen — the old Google-only shortcut left
              phone/email members creating NAMELESS homes at this subdomain (rich-phone3). */}
          {onCreate && (
            <button className="btn-primary" onClick={() => onCreate(name)}>Create {nameLabel(name)}</button>
          )}
          {googleEnabled && (
            <button className={onCreate ? 'btn-ghost onboarding-secondary' : 'btn-primary'} onClick={() => continueWithGoogle(name)}>Create it with Google</button>
          )}
        </>
      ) : (
        // A named-home sign-in uses THIS home's own credential(s). Google is NOT shown — it
        // resolves the member's separate Google home, not this named one.
        <>
          {(info?.connectionAddress || (info?.connectionKind && CONNECTION_LABEL[info.connectionKind])) && (
            <p className="onboarding-hint" style={{ fontSize: '.8rem', color: '#475569' }}>
              ↳ Connect {nameLabel(name)} with{info?.connectionKind && CONNECTION_LABEL[info.connectionKind] ? <> its <strong>{CONNECTION_LABEL[info.connectionKind]}</strong></> : ' your published'} credential
              {info?.connectionAddress && (
                <> · account{' '}
                  <code title={info.connectionAddress} style={{ fontFamily: 'ui-monospace, Menlo, monospace' }}>
                    {`${info.connectionAddress.slice(0, 6)}…${info.connectionAddress.slice(-4)}`}
                  </code>
                </>
              )}
            </p>
          )}
          {/* Social (OIDC/KMS) custodian → the credential's own sign-in is the primary CTA; the unpublished-kind
              fallback offers only the social ways in THIS deployment opens (`named-home-door.ts` says why). */}
          {socialButtons.map(({ provider, primary }) => (
            <button key={provider} className={primary ? 'btn-primary' : 'btn-ghost onboarding-secondary'} onClick={() => (provider === 'youversion' ? continueWithYouVersion(name) : continueWithGoogle(name))}>
              Continue with {provider === 'youversion' ? 'YouVersion' : 'Google'}
            </button>
          ))}
          {/* Say WHY the passkey buttons are absent. Silently dropping them from a home that HAS passkeys
              reads as the home losing them; this is a property of the chain, and it is not the member's
              to fix. */}
          {info?.hasPasskey && passkeyUnverifiable && (
            <p className="onboarding-hint" style={{ fontSize: '.8rem', color: '#475569' }}>
              ↳ This home has a passkey, but the network it runs on cannot verify passkey signatures yet,
              so passkey sign-in is unavailable here. Use the credential below that opened this home.
            </p>
          )}
          {showPasskey && passkeyEnabled && (
            <button className={socialKind && !passkeyFirst ? 'btn-ghost onboarding-secondary' : 'btn-primary'} onClick={() => go('passkey')}>Continue with passkey</button>
          )}
          {showPasskey && passkeyEnabled && (
            <button className="btn-ghost onboarding-secondary" onClick={() => go('passkey', 'discoverable')}>
              Use synced or phone passkey
            </button>
          )}
          {/* A social (OIDC/KMS) custodian is NOT a user wallet — suppress the misleading wallet CTA for it
              (its KMS address only LOOKS like an EOA). */}
          {showWallet && walletEnabled && !socialKind && (
            <button className={onlyWallet ? 'btn-primary' : 'btn-ghost onboarding-secondary'} onClick={() => go('wallet')}>
              Continue with wallet
            </button>
          )}
          {/* Email/phone-custodied home: sign in with the code sent to the email/number that opens this home. */}
          <button className="btn-ghost onboarding-secondary" style={showEmail ? SELECTED_METHOD_STY : undefined} aria-pressed={showEmail} onClick={() => { setShowEmail((v) => !v); setShowPhone(false); }}>
            Continue with email
          </button>
          {showEmail && <div style={{ margin: '.4rem 0 .2rem' }}><EmailAuthCard /></div>}
          {phoneEnabled && (
            <button className="btn-ghost onboarding-secondary" style={showPhone ? SELECTED_METHOD_STY : undefined} aria-pressed={showPhone} onClick={() => { setShowPhone((v) => !v); setShowEmail(false); }}>
              Continue with phone
            </button>
          )}
          {phoneEnabled && showPhone && <div style={{ margin: '.4rem 0 .2rem' }}><PhoneAuthCard /></div>}
        </>
      )}
      {err && <p className="onboarding-hint taken">{err}</p>}
      {/* The agent behind this door is public (card, endpoint, address) — say so to whoever arrives, with the
          way Claude reaches it. Only once the home is known to exist: an unclaimed name has no agent. */}
      {info?.exists !== false && info?.agent && <AgentReachFold name={name} agent={info.agent} />}
    </Shell>
  );
}

// ── Org-create consent (existing member creates an org via a relying app) ──────
function OrgConsent({ personAgent, api }: { personAgent: Address; api: ReturnType<typeof useEnrollReq> }) {
  // Only a pinned `existing_org` skips the chooser. An `org_base` request still routes through
  // it: with no eligible existing org the chooser auto-creates under that name (no screen);
  // with eligible orgs it offers them — never a silent duplicate of one the person stewards.
  // workspace-create is a named deploy of a service-class workspace agent — not an org picker.
  const isWorkspace = api.enroll?.template === 'workspace-create';
  const preselected = !!api.enroll?.existingOrg;
  const [phase, setPhase] = useState<'choose' | 'consent' | 'busy' | 'connected' | 'error'>(
    preselected || isWorkspace ? 'consent' : 'choose',
  );
  const [choice, setChoice] = useState<OrgChoice | null>(null);
  const [err, setErr] = useState('');
  const [grantProgress, setGrantProgress] = useState<{
    step: number;
    total: number;
    label: string;
    hint?: string;
  }>({
    // Total unknown (no counter) until the ceremony names its own: a select-existing connect is 3
    // steps, not the 5 this placeholder used to promise (see CeremonyProgress).
    step: 1,
    total: 0,
    label: 'Starting…',
    hint: 'This can take a moment.',
  });
  const { session } = useSession();
  const orgClient = api.enroll
    ? (whitelabel.relyingApps.find((a) => a.client_id === api.enroll!.aud) ?? knownRelyingClient(api.enroll.aud))
    : undefined;
  const tplId = isWorkspace ? 'workspace-create' : 'org-create';
  // The client's own wording wins when it registered one for this template (no-op for every other app).
  const tpl = withClientConsent(
    whitelabel.delegationTemplates[tplId] ?? { canDo: [], cannotDo: ['Move funds', 'Add members', 'Act outside this permission'] },
    orgClient,
    tplId,
  );
  // An app speaking in its own words also doesn't place the org "in the <community>" — that is the Home's
  // vocabulary, not the app's (Gather27: a church listing a group).
  const ownWording = Boolean(orgClient?.consent?.templates?.[tplId]);
  const orgAppName = displayAppName(orgClient?.name, api.host);
  const orgAppDomain = displayAppDomain(api.host);
  // The person's chooser pick wins over the URL's suggestion.
  const orgBase = choice?.orgName ?? api.enroll?.orgBase ?? '';
  const existingOrg = choice?.existingOrg ?? api.enroll?.existingOrg;
  // spec 256 — the org inherits the member's ACTUAL custody. A Google member's org is deployed by
  // their KMS C_sub server-side (zero device prompts); passkey/wallet members sign on device. The
  // credential is the one they're signed in with (via is 'passkey' | 'wallet' | 'Google').
  //
  // BUT org-create arrives with `?delegate`, which makes `shouldRestore()` SKIP session restoration, so
  // `useSession()` is null here for a Google/wallet member. Their custody token still lives in the
  // cross-subdomain SSO cookie (set at Google sign-in — GoogleEnrollResume / openSession). Recover it as
  // a fallback so we route to the Google KMS path instead of erroring "your passkey isn't on this device."
  // A passkey member has no reusable token; they fall through to `via='passkey'` and the ambient passkey,
  // which is correct.
  const cred = session ?? readSsoCookie();
  const credVia = (cred?.via ?? '').toLowerCase();
  // Resolve the org-create signing credential. The cookie `via` is authoritative when it names a real
  // credential; otherwise (cookie absent / `via:'sso'` placeholder) DON'T blindly default to passkey — a
  // WALLET member has no passkey on this device, so a passkey ceremony errors "your central-auth passkey
  // isn't on this device" (the #349 class). Fall back to WALLET when there's no passkey on this device AND a
  // wallet is injected (createChildAgentForSite then deploys an eoa-custodied org via personalSign); else
  // passkey. Google/YouVersion are KMS — signed server-side with the session token.
  const via: Via =
    credVia === 'google' ? 'google'
    : credVia === 'youversion' ? 'youversion'
    // Email/phone are KMS-family (server-side C_sub signing with the session token) — treating
    // them as passkey errored "your central-auth passkey isn't on this device" mid-org-create.
    : credVia === 'email' ? 'email'
    : credVia === 'phone' ? 'phone'
    : credVia === 'wallet' ? 'wallet'
    : (!loadPasskey() && hasWallet()) ? 'wallet'
    : 'passkey';
  const auth: Auth | undefined = cred?.token ? { token: cred.token } : undefined;

  async function authorize() {
    if (!api.enroll) return;
    setPhase('busy');
    try {
      // SEC-001: registry-derived delegate FROM the server-minted grant (the URL's
      // `api.enroll.delegate` is treated as untrusted hint — the server's binding wins).
      const { grant_id, delegate } = await api.beginGrant(api.enroll.name);
      let created: Awaited<ReturnType<typeof createOrganization>>;
      if (isWorkspace) {
        const name = orgBase.trim();
        if (name.length < 3) { setErr('Name this field workspace — at least 3 characters.'); setPhase('error'); return; }
        if (!auth?.token) { setErr('Your Home session is needed to create a workspace.'); setPhase('error'); return; }
        // THE ORGANIZATION FIRST, THEN THE WORKSPACE UNDER IT (`createGovernedWorkspace`, the same road the
        // recognized path takes): a workspace agent is a service and holds no members, so `<name>.org` governs
        // `<name>.workspace`, and the token's `org` payload — still the workspace's — names the governor.
        created = await createGovernedWorkspace({ address: personAgent, name: api.enroll.name }, name, delegate, via, auth, {
          purpose: api.enroll.purpose ?? 'field-workspace',
          requestedBy: api.enroll.aud,
          grantOrg: api.enroll.grantOrg,
          onProgress: setGrantProgress,
        });
      } else {
        created = await createOrganization({ address: personAgent, name: api.enroll.name }, orgBase, delegate, via, auth, {
          purpose: api.enroll.purpose,
          requestedBy: api.enroll.aud,
          grantOrg: api.enroll.grantOrg,
          existingOrg,
          signAsOrg: choice?.asSteward,
          onProgress: setGrantProgress,
        });
      }
      if (!created.ok) { setErr(created.error); setPhase('error'); return; }
      const proved = await personGrantForOrgCreate({ address: personAgent, name: api.enroll.name }, delegate, via, auth, created);
      if (!proved.ok) { setErr(proved.error); setPhase('error'); return; }
      const code = await api.submitGrant(grant_id, proved.grant, proved.org);
      setPhase('connected');
      setTimeout(() => api.deliverCode(code), 400);
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'org creation failed');
      setPhase('error');
    }
  }

  if (phase === 'choose') {
    return (
      <Shell>
        <OrgChooser
          token={cred?.token}
          appHost={api.host}
          appName={orgAppName}
          purpose={api.enroll?.purpose}
          defaultName={api.enroll?.orgBase}
          onChoose={(c) => { setChoice(c); setPhase('consent'); }}
          onDecline={api.denyEnroll}
        />
      </Shell>
    );
  }
  if (phase === 'busy') {
    return (
      <Shell>
        <CeremonyProgress
          label={clientProgressText(orgClient, grantProgress.label)}
          hint={clientProgressText(orgClient, grantProgress.hint ?? (existingOrg ? `${orgAppName} is connecting — this stays in your control.` : isWorkspace ? 'This can take a moment — we’re setting the organization and its workspace up.' : 'This can take a moment — we’re setting the organization up.'))}
          step={grantProgress.step}
          total={grantProgress.total}
        />
      </Shell>
    );
  }
  // Spec 255 W4.1 — the org-create "connected" receipt: what the single approval accomplished.
  if (phase === 'connected') return <Shell><BrandShield size={56} /><h1 className="onboarding-h1">{orgBase} is ready</h1><ReceiptCard title={`${orgBase} is ready`} body={existingOrg ? `${orgAppName} can now read what it posts — the organization stays in your control.` : isWorkspace ? `The organization and its workspace are started, their names are claimed, and ${orgAppName} can act as this workspace — revocably.` : orgCreateText(orgClient, 'receipt', { app: orgAppName, org: orgBase }, `Its home is started, its name is claimed, and ${orgAppName} can now read what it posts.`)} /><p className="onboarding-sub">Returning you to {orgAppName}…</p><WorkingBar /></Shell>;
  if (phase === 'error') return <Shell><h1 className="onboarding-h1">Couldn&apos;t finish</h1><p className="onboarding-hint taken">{err}</p><button className="btn-primary" onClick={() => setPhase(preselected ? 'consent' : 'choose')}>Try again</button></Shell>;
  return (
    <Shell>
      {/* Spec 255 W3.3 — pre-org-create explainer ABOVE the consent sheet. Consent-level copy (NOT
          passkey-specific — never says "passkey"), so it's correct for ALL org-create credentials
          including Google. */}
      <div className="securing-explainer pre-prompt-explainer">
        <div className="securing-explainer-title">One tap — approve {existingOrg ? `connecting ${orgBase}` : `creating ${orgBase}`}</div>
        <p>
          {existingOrg
            ? `This single approval lets ${orgAppName} read what ${orgBase} posts. Nothing beyond that — no new organization is created.`
            : isWorkspace
              ? `This single approval starts an organization under your name and the workspace it governs, claims both names, and lets ${orgAppName} act as that workspace. Nothing beyond that.`
              : orgCreateText(orgClient, 'explainer', { app: orgAppName, org: orgBase }, `This single approval starts the organization, claims its name, and lets ${orgAppName} read what it posts. Nothing beyond that.`)}
        </p>
        <p className="securing-wait">{orgCreateText(orgClient, 'disconnect', { app: orgAppName, org: orgBase }, `You can disconnect ${orgAppName} at any time from your Impact home.`)}</p>
      </div>
      <ConsentSheet
        title={existingOrg ? `Connect ${orgBase} to ${orgAppName}` : isWorkspace ? `Create ${orgBase} and its workspace` : ownWording ? `Create ${orgBase}` : `Create ${orgBase} in the ${whitelabel.brand.community}`}
        appName={orgAppName}
        appDomain={orgAppDomain}
        appDescription={orgClient?.description}
        template={tpl}
        authorizeLabel="Approve & connect"
        onAuthorize={authorize}
        onDecline={api.denyEnroll}
      />
    </Shell>
  );
}
