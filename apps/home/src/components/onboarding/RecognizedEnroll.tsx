'use client';
import { WorkingBar } from './WorkingBar';
// Recognized-member fast-path for a relying-app site-login enroll (extends the ADR-0032 custody
// boundary to the redirect path). An ALREADY-AUTHENTICATED member arriving at a connect request is
// recognized from the cross-subdomain `ap_sso` cookie — no "Welcome / sign in or get started". We
// authorize in ONE step, routing by custody:
//
//   • Google/KMS or wallet — signing is origin-agnostic (server-side KMS, or MetaMask personalSign)
//     → authorize HERE, on whatever Connect origin the enroll landed on.
//   • passkey — the credential's rpId IS the home subdomain (`lib/passkey.ts`: rpId = hostname, and
//     that rpId is even mixed into the SA's CREATE2 salt), so it can ONLY sign on `<label>.<domain>`.
//     If we're not already there, hop to the home subdomain carrying the enroll params; the passkey
//     then signs locally. One tap, no re-login.
//
// On authorize we run the SAME grant pipeline as GoogleEnrollResume:
//   beginEnrollmentGrant → givePermission(via) → submitEnrollGrant → deliverEnrollCode.
//
// Recognition is best-effort: a missing/stale cookie (no session, undeployed SA, fetch fail) calls
// `onUnrecognized()` and the caller falls back to the credential-first entry (ADR-0013 — one explicit
// fallback, never a silent second mechanism).
import { useCallback, useEffect, useRef, useState } from 'react';
import type { Address } from '@agenticprimitives/types';
import { givePermission, createOrganization, createGovernedWorkspace, personGrantForOrgCreate, collectDueSubscriptions, authorizeContentSigningForOwner,
  authorizeServiceAgentWire, activateVaultIfNeeded, activateInboxDeliveryIfNeeded, activateInteractionsIfNeeded,
  isKmsVia, resolveVia, publishSocialConnectionKindIfNeeded, signHashFor, type Via, type Auth } from '../../home/onboarding';
import { issueAskAsMeDelegation, issueOrganizationResourceAccessDelegation, issueSiteDelegation, issueWorkspaceMembershipAccessDelegation, ORG_INTERACTIONS_SESSION_LEAF_TTL_SECONDS, toWire, type DelegationWire } from '../../lib/delegation';
import { offerRelationshipCredential, relationshipOfferOf, resolveWorkspaceGovernor, type RelationshipOfferV1 } from '../../lib/workspace-governor';
import { roleSlugOf } from '../../lib/org-role';
import { buildActAsMeSet, signActAsMeSet, type ActChoice } from '../../lib/act-as-me';
import { ActAsMeConsent } from './ActAsMeConsent';
import { approveGrantHashes, signsWithoutPrompt } from '../../connect-client';
import { issueAppReadGrantIfDeclared } from '../../home/app-read-grant';
import { MCP_SERVER_ID } from '../../lib/inbox-delivery';
import { clearStandingGrant } from '../../lib/grant-cache';
import { homeLabel, type Home } from '../../home/types';
import { whitelabel, fmt, isPaymentTemplate } from '../../whitelabel/config';
import { createManagedAgent, fetchProfile, listManagedAgents, resolveHomeNameForLabel, resolveTreasuryByConvention } from '../../connect-client';
import { readSsoCookie, setSsoCookie, clearSsoCookie } from '../../lib/sso-cookie';
import { nameLabel, subdomainHandle, personalAuthOrigin } from '../../lib/domain';
import { recordConnectedApp } from '../../lib/connected-apps';
import { provisionCommunityMessaging } from '../../lib/messaging-ceremony';
import { provisionsCommunityMessaging, reusesStandingGrantWithSelfVault } from '../../whitelabel/provisioning';
import { setFedcmLoginStatus } from '../../context/session';
import { beginEnrollmentGrant, hostOf, submitEnrollGrant, deliverEnrollCode, deliverCollectResult, type EnrollApi, isCeremonyTemplate, isDeployTemplate } from './useEnrollReq';
import { BrandShield } from '../shared/BrandShield';
import { ReceiptCard } from '../shared/ReceiptCard';
import { ConsentSheet } from '../shared/ConsentSheet';
import { CeremonyProgress } from './CeremonyProgress';
import { coinMandateLeg, grantsCoinAtConnect, withCurrencyConsent, withEmailClaimConsent, withProfileNameConsent } from '../../lib/new-member';
import { OrgChooser, type OrgChoice } from './OrgChooser';
import { displayAppDomain, displayAppName } from './org-chooser-label';
import { knownRelyingClient } from '../../lib/relying-clients';
import { agentClassOf } from '../../lib/agent-class';
import { withMissionRegistry } from '../../lib/mission-registry';
import { profileForConnect } from '../../lib/connect-profile-name';
import { clientOrgName, clientProgressText, hidesIdentifiers, signedInLabel, switchAccountLabel, withClientConsent } from '../../whitelabel/client-consent';
import { verifiedEmailFor } from '../../lib/verified-email';

/** The kinds of agent that ARE an organization holding its own members — where a team-scoped role can be offered. A
 *  workspace is not one (a service, with no members): its people belong to the organization that governs it. */
const TEAM_CLASS = new Set(['team', 'org', 'organization', 'circle', 'church', 'household']);

type Phase = 'resolving' | 'choose-org' | 'consent' | 'granting' | 'connected' | 'error';

/** What a person is told at a workspace with no governing organization (2026-10-02): membership is recorded on
 *  organizations only, so neither an invitation into it nor a join of it can succeed until its host runs the
 *  migration. One sentence, used by both ceremonies, so the host and the invitee read the same thing. */
const LEGACY_WORKSPACE_MESSAGE = 'This workspace has no organization yet. Its host has to set one up before anybody can join (apps/home/scripts/workspace-governor.mts).';

/** The CAIP-10 tail (`eip155:<chain>:0x…` → `0x…`), or null. Mirrors context/session. */
function addressOf(caip10: string | undefined): Address | null {
  if (!caip10) return null;
  const tail = caip10.split(':').pop();
  return tail && /^0x[0-9a-fA-F]{40}$/.test(tail) ? (tail as Address) : null;
}

/** The `sub` claim of a JWT, by client-side payload decode. Used ONLY to BIND an owner-op to the owner the
 *  relying app authenticated (the real authz is the owner-signed leaf + the a2a calls' server-side
 *  verifyIdToken). Returns undefined when the token is absent or unparseable. */
function idTokenSub(jwt: string | undefined): string | undefined {
  if (!jwt) return undefined;
  try {
    const payload = jwt.split('.')[1];
    if (!payload) return undefined;
    const claims = JSON.parse(atob(payload.replace(/-/g, '+').replace(/_/g, '/'))) as { sub?: unknown };
    return typeof claims.sub === 'string' ? claims.sub : undefined;
  } catch {
    return undefined;
  }
}

export function RecognizedEnroll({ api, onUnrecognized }: { api: EnrollApi; onUnrecognized: () => void }) {
  const c = whitelabel.copy;
  const ran = useRef(false);
  const [phase, setPhase] = useState<Phase>('resolving');
  const [grantProgress, setGrantProgress] = useState<{
    step: number;
    total: number;
    label: string;
    hint?: string;
  }>({
    // Total UNKNOWN (0 = no counter) until the ceremony that runs names its own. This used to say 3,
    // which the plain sign-in happens to use, so an org-create (5 steps) showed "Step 1 of 3" through
    // the pre-ceremony legs — beginEnrollmentGrant's profile read alone can take 5 s — then jumped to
    // "Step 2 of 5" when createOrganization spoke. See CeremonyProgress.
    step: 1,
    total: 0,
    label: 'Starting…',
    hint: 'This can take a moment.',
  });
  const [home, setHome] = useState<Home | null>(null);
  const [viaLower, setViaLower] = useState<Via>('passkey');
  const [token, setToken] = useState('');
  // Spec 397 §11 — the act set the person checked (ActAsMeConsent); read at authorize time, never re-rendered into.
  const actChoices = useRef<{ choices: ActChoice[]; problem: string | null }>({ choices: [], problem: null });
  const onActChoices = useCallback((choices: ActChoice[], problem: string | null) => { actChoices.current = { choices, problem }; }, []);
  const [error, setError] = useState('');
  // Chooser-mode org-create (spec 246 select-existing): the enroll carries NO org_base/existing_org —
  // the member picks a stewarded org (grant-only) or names a new one HERE before consenting.
  const [orgSel, setOrgSel] = useState<OrgChoice | null>(null);

  const enroll = api.enroll;
  const relyingApp = enroll
    ? (whitelabel.relyingApps.find((a) => a.client_id === enroll.aud) ?? knownRelyingClient(enroll.aud) ?? undefined)
    : undefined;
  /** The ordinary sign-in, as opposed to a named ceremony run on the way into one. */
  const plainSignIn = !enroll?.template || enroll.template === 'site-login';
  const appHost = enroll ? hostOf(enroll.redirectUri) : '';
  // A Home MCP connects on behalf of a HOST (Claude, Muse, …): the consent names the host, and the registered client's
  // name becomes the "through" line, so the person reads who is asking rather than which relay carries it.
  const registeredName = displayAppName(relyingApp?.name, appHost);
  const appName = enroll?.viaHost ? enroll.viaHost : registeredName;
  const appDomain = displayAppDomain(appHost);
  // A client that registered `consent.signedInAs: 'email'` (Gather27 — email is its only way in) names
  // the person by the address they signed in with rather than `0x6a25…f058`. Read from their OWN vault
  // over their own session (profileForConnect: best-effort, 5 s cap); no email → the usual rule.
  // The email verified a moment ago in THIS window (the code step, lib/verified-email.ts) is used first —
  // it needs no round trip, so the line never falls back to an address while the profile read runs.
  const [signedInEmail, setSignedInEmail] = useState('');
  const hideIds = hidesIdentifiers(relyingApp);
  const wantsEmailLabel = relyingApp?.consent?.signedInAs === 'email' || hideIds;
  useEffect(() => {
    if (!wantsEmailLabel || !home?.address) return;
    const known = verifiedEmailFor(home.address);
    if (known) { setSignedInEmail(known); return; }
    let live = true;
    void profileForConnect().then((p) => { if (live && p.email) setSignedInEmail(p.email); });
    return () => { live = false; };
  }, [wantsEmailLabel, home?.address]);
  const signedInAs = signedInLabel(relyingApp, { email: signedInEmail, name: home?.name, address: home?.address });

  const fail = (e: unknown) => {
    setError(e instanceof Error ? e.message : typeof e === 'string' ? e : 'Something went wrong');
    setPhase('error');
  };

  // Recover the session from the cross-subdomain cookie, resolve the member, and route by custody.
  useEffect(() => {
    if (ran.current || !enroll) return;
    ran.current = true;
    void (async () => {
      // Force the custodian chooser ONCE (clear the active session → credential-first entry) instead of
      // silently reusing whatever session this browser already holds. Critical for multi-custodian admin
      // (each identity has its own SIWE/social/passkey custodian): authorizing demo-validator.impact must
      // never default to the lbsb/deployer custodian's leftover session. Triggers:
      //   • OIDC prompt=select_account/login — the relying app explicitly asked to re-choose.
      //   • a NAMELESS connect-type enroll (`agent_name` omitted on site-login / x402-pay) — the request
      //     pins NO specific home, so we must NOT assume the active session's identity. A PINNED connect
      //     (agent_name set) still one-taps. OWNER-operation templates (org-create / subscription-collect /
      //     content-signer / service-agent-wire) deliberately reuse the recognized owner session, so
      //     they're exempt. MISSING ONE HERE IS SILENT: an owner-op sent with no `agent_name` (which the
      //     nameless connect shape uses) forces the chooser, drops out to `onUnrecognized`, and the request
      //     completes down the ordinary site-login pipeline — one signature, a bare `?code`, and the
      //     ceremony's own branch below never runs. That is what happened to service-agent-wire.
      const ownerOp = isDeployTemplate(enroll.template) || isCeremonyTemplate(enroll.template);
      const forceChooser =
        enroll.prompt === 'select_account' || enroll.prompt === 'login' || (!enroll.name && !ownerOp);
      if (forceChooser) {
        const k = `ap_chooser:${enroll.state || enroll.codeChallenge}`; // per-attempt (state may be empty)
        if (!sessionStorage.getItem(k)) {
          sessionStorage.setItem(k, '1'); // one-time: after the chooser + re-sign-in, proceed normally (no loop)
          clearSsoCookie();
          return onUnrecognized(); // → EntryExperience: wallet/SIWE · Google · YouVersion · passkey
        }
      }
      const sso = readSsoCookie();
      // OWNER ops (content-signer / subscription-collect, spec 266/272) MUST run on a genuine HOME SESSION:
      // it is the authoritative carrier of (a) the SA, (b) the real credential kind (principal.kind → how to
      // sign), and (c) a token that authorizes SERVER-SIDE (social/KMS) leaf signing — uniformly across
      // passkey / social / SIWE. The relying-app `collectToken` is only a BINDING HINT + the downstream a2a
      // bearer, never the identity source (an id_token has no credential kind and can't authorize KMS).
      // No cookie → onUnrecognized → credential-first entry; after sign-in, EntryExperience re-enters the
      // recognized path (Step 3) and we run the ceremony on that fresh home session.
      if (!sso?.token) return onUnrecognized(); // not signed in → credential-first entry
      const profile = await fetchProfile(sso.token).catch(() => null);
      const addr = addressOf(profile?.agent);
      // A valid, DEPLOYED member is required to authorize a delegation; anything else → sign in fresh.
      if (!profile || !addr || profile.deployed === false) return onUnrecognized();
      // ENFORCE the pin: a PINNED connect (agent_name set) is exempt from the forced chooser precisely
      // BECAUSE it names its identity — so the active session MUST actually be that identity. A different
      // leftover session (e.g. a wallet owner-identity from a signer ceremony) must never silently
      // authorize — or sign — for the pinned home (it would flip the relying app's identity AND route
      // signing to the wrong custodian, e.g. MetaMask for a Google home). Mismatch → re-choose credentials.
      const pinned = nameLabel(enroll.name ?? '');
      if (pinned && nameLabel(profile.name ?? '') !== pinned) {
        console.warn('[connect] pinned identity ≠ active session — re-choosing credentials', { pinned, session: profile.name });
        clearSsoCookie();
        return onUnrecognized();
      }
      // BIND the owner-op to the owner the relying app authenticated: the home session's SA MUST equal the
      // `collectToken` subject. Otherwise a relying app could start an owner-op for a DIFFERENT owner than
      // the one it authenticated. Mismatch → reject (the user must sign in as the named owner / decline).
      if (isCeremonyTemplate(enroll.template)) {
        const want = addressOf(idTokenSub(enroll.collectToken));
        if (!want) return fail('This authorization request is missing its owner token.');
        if (want.toLowerCase() !== addr.toLowerCase()) {
          return fail(
            `This authorization is for a different owner than your current session. Sign out and sign back in as the owner of ${want}.`,
          );
        }
      }
      // Sign with the credential that actually authenticated this session (wallet/passkey/KMS), not the
      // cookie's defaulted via — which sent a wallet member to passkey at authorize time.
      const v = resolveVia(profile.credential, sso.via);

      // passkey is rpId-bound to the home subdomain — hop there if we're not already on it (the passkey
      // can't assert at the apex). Google/KMS + wallet sign on any origin, so they authorize in place.
      const label = nameLabel(profile.name ?? '');
      if (v === 'passkey') {
        if (!label) return onUnrecognized(); // passkey with no resolvable home — can't route, sign fresh
        if (subdomainHandle() !== label) {
          // Carry the enroll params across the hop so the subdomain re-enters enroll mode + recognizes us.
          window.location.href = personalAuthOrigin(label) + '/' + window.location.search;
          return;
        }
      }
      setHome({ address: addr, name: profile.name ?? '' });
      setViaLower(v);
      setToken(sso.token);
      // Org-create without a pinned `existing_org` → the chooser decides. With `org_base` and
      // no eligible existing org it auto-creates under that name (no screen); with eligible
      // orgs it offers them — the app naming a new org must not silently mint a duplicate of
      // one the person already stewards. Everything else goes straight to consent.
      setPhase(enroll.template === 'org-create' && !enroll.existingOrg ? 'choose-org' : 'consent');
    })();
  }, [enroll, onUnrecognized]);

  async function onAuthorize() {
    if (!enroll || !home) return;
    setPhase('granting');
    try {
      // spec 272 recurring — OWNER subscription collection. No grant/delegation: the owner signs the
      // redemption of every DUE subscriber's standing pull mandate AS the collection treasury they custody,
      // then we deliver the result back to the owner app. Reuses the recognized-owner auth resolved above.
      if (enroll.template === 'subscription-collect') {
        const cfg = relyingApp?.collectionConfig;
        if (!cfg) return fail('this app is not configured for subscription collection');
        if (!enroll.collectToken) return fail('missing owner token for collection');
        // Same reason as the grant path: the demo-custody probe needs the token on the wallet via.
        const collectAuth: Auth | undefined = token ? { token } : undefined;
        const res = await collectDueSubscriptions(
          cfg.treasury as Address, viaLower, collectAuth,
          { asset: cfg.asset as Address, edition: cfg.edition, a2aBase: cfg.a2aBase, idToken: enroll.collectToken },
        );
        if (!res.ok) return fail(res.error);
        setSsoCookie(token, viaLower);
        setPhase('connected');
        setTimeout(() => deliverCollectResult(enroll, api.popupMode, { collected: res.collected, attempted: res.attempted }), 900);
        return;
      }
      // spec 266 delegated content trust — OWNER authorizes each content issuer's Cloud-KMS signing key.
      // No grant: the owner signs, per issuer they custody, the issuer SA → KMS-key delegation; the content
      // service stores it. Reuses the recognized-owner auth + the relying app's collectionConfig.a2aBase.
      if (enroll.template === 'content-signer') {
        const cfg = relyingApp?.collectionConfig;
        if (!cfg) return fail('this app is not configured for content-signer authorization');
        if (!enroll.collectToken) return fail('missing owner token for content-signer authorization');
        // Same reason as the grant path: the demo-custody probe needs the token on the wallet via.
        const csAuth: Auth | undefined = token ? { token } : undefined;
        const res = await authorizeContentSigningForOwner(viaLower, csAuth, { a2aBase: cfg.a2aBase, idToken: enroll.collectToken, targetSigner: enroll.contentSignerTarget });
        if (!res.ok) return fail(res.error);
        setSsoCookie(token, viaLower);
        setPhase('connected');
        setTimeout(() => deliverCollectResult(enroll, api.popupMode, { collected: res.authorized, attempted: res.attempted }, 'content-signer'), 900);
        return;
      }
      // agent-rule `service-agent-signing.md` — the custodian of a named agent authorizes a relying
      // service's KMS key to sign AS it. No grant is minted here: what the ceremony produces is a
      // WIRE the service stores, so the service holds a revocable delegate and never the identity.
      if (enroll.template === 'service-agent-wire') {
        const cfg = relyingApp?.serviceAgentConfig;
        if (!cfg) return fail('this app is not configured for service-agent authorization');
        if (!enroll.collectToken) return fail('missing owner token for service-agent authorization');
        // Same reason as the grant path: the demo-custody probe needs the token on the wallet via.
        const swAuth: Auth | undefined = token ? { token } : undefined;
        // `grant_org` names the agent the service is to act AS (a card-room club's workspace, 2026-09-13); without
        // it the service names its own identity, as before.
        const res = await authorizeServiceAgentWire(viaLower, swAuth, { a2aBase: cfg.a2aBase, idToken: enroll.collectToken, ...(enroll.grantOrg ? { identity: enroll.grantOrg } : {}) });
        if (!res.ok) return fail(res.error);
        setSsoCookie(token, viaLower);
        setPhase('connected');
        setTimeout(() => deliverCollectResult(enroll, api.popupMode, { collected: 1, attempted: 1 }, 'service-agent-wire'), 900);
        return;
      }
      // Spec 397 — `ask-as-me`: the Home MCP (Claude's entrance to this person's agent) asks for ONE thing — a
      // delegation from the person to the Home MCP's key, pinned to `harness.ask` and time-boxed: the right to put
      // a question to their agent as them, and nothing more (every act still parks for their signature). Minted
      // and signed here by the person's own credential, bound to the server-minted grant like a site login; the
      // relying app receives it on the token exchange and holds it, revocable on chain, in the person's name.
      // Spec 397 §11 — `act-as-me`: the ask wire as above PLUS the act set she checked — one standing wire per act,
      // from her (her treasury for a payment) to the client's ACT key, 30 days, revocable one by one. One ceremony:
      // a prompt-free custodian signs each digest; a passkey approves each delegator's digests in one batch (a
      // payment wire is her treasury's — a second prompt, never a hidden one). Nothing here is a mandate.
      if (enroll.template === 'act-as-me') {
        const { choices, problem } = actChoices.current;
        if (problem) return fail(`Before you authorize: ${problem}.`);
        if (choices.length === 0) return fail('Check at least one act to pre-authorize, or decline.');
        const askDelegate = relyingApp?.ask_delegate;
        if (!askDelegate) return fail('This client has no ask key registered — it cannot hold an act set.');
        const n = choices.length;
        setGrantProgress({ step: 1, total: 3, label: 'Authorizing this assistant to ask your agent as you…' });
        const { grant_id: actGrantId, delegate: actDelegate } = await beginEnrollmentGrant(enroll, home.name);
        const auth: Auth | undefined = token ? { token } : undefined;
        const signPerson = await signHashFor(viaLower as Via, home.address, auth);
        const askWire = await issueAskAsMeDelegation(home.address, askDelegate, signPerson);
        setGrantProgress({ step: 2, total: 3, label: `Signing ${n} standing wire${n === 1 ? '' : 's'} for the acts you checked…` });
        const set = buildActAsMeSet(home.address, actDelegate, choices);
        const promptFree = await signsWithoutPrompt(viaLower, token);
        const signed = await signActAsMeSet(set, promptFree
          ? { mode: 'each', sign: async (delegator, digest) => (await signHashFor(viaLower as Via, delegator, auth))(digest) }
          : { mode: 'batch', approve: async (delegator, digests) => { const r = await approveGrantHashes(delegator, await signHashFor(viaLower as Via, delegator, auth), digests); if (!r.ok) throw new Error(r.error); } });
        setGrantProgress({ step: 3, total: 3, label: 'Finishing…' });
        const actCode = await submitEnrollGrant(actGrantId, toWire(askWire), undefined, undefined, undefined, undefined, undefined, undefined, undefined, signed);
        setSsoCookie(token, viaLower);
        setPhase('connected');
        setTimeout(() => deliverEnrollCode(enroll, api.popupMode, actCode), 600);
        return;
      }
      if (enroll.template === 'ask-as-me') {
        setGrantProgress({ step: 1, total: 2, label: 'Authorizing this assistant to ask your agent as you…' });
        const { grant_id: askGrantId, delegate: askDelegate } = await beginEnrollmentGrant(enroll, home.name);
        const askAuth: Auth | undefined = token ? { token } : undefined;
        const signHash = await signHashFor(viaLower as Via, home.address, askAuth);
        const wire = await issueAskAsMeDelegation(home.address, askDelegate, signHash);
        // Spec 412 W6 — the app's declared read grant rides the same ceremony (best-effort, said).
        await issueAppReadGrantIfDeclared(enroll.aud, home.address, signHash);
        setGrantProgress({ step: 2, total: 2, label: 'Finishing…' });
        const askCode = await submitEnrollGrant(askGrantId, toWire(wire));
        setSsoCookie(token, viaLower);
        setPhase('connected');
        setTimeout(() => deliverEnrollCode(enroll, api.popupMode, askCode), 600);
        return;
      }
      // SEC-001: server-mint the grant FIRST; use the registry-derived delegate (anti-spoof).
      const tCeremony = Date.now();
      const lapCeremony = (what: string) => console.info(`[connect ${enroll.template}] ${what} +${Date.now() - tCeremony}ms`);
      const { grant_id, delegate } = await beginEnrollmentGrant(enroll, home.name);
      lapCeremony('grant begun');
      /*
        PASS THE SESSION TOKEN FOR EVERY CREDENTIAL, not only the KMS ones.

        `signHashFor` uses it two ways, and gating on `isKmsVia` served only the first:
          KMS   — the token IS the signer.
          WALLET — the token runs the DEMO-CUSTODY probe. A seeded demo person has a wallet
            CREDENTIAL whose key this Home holds and a browser with no wallet, so
            `isDemoCustodyHome(token)` is what routes them to a prompt-free server-side signature.

        Withholding it left `auth?.token` undefined, the probe never ran, and the wallet branch fell
        through to the injected provider — "No Ethereum wallet found" at the last click of a ceremony
        for an account whose key cannot be in that browser.

        Real wallet homes are unaffected: the probe answers false once per session and falls through.
      */
      const auth: Auth | undefined = token ? { token } : undefined;

      // ONE managed-agents projection read serves both the treasury resolution (payment apps only)
      // and the messaging leg after the grant — it used to be fetched twice, serially, at ~1.5–3s
      // a call. Started here so it overlaps the grant ceremony instead of extending it.
      // ...and NOT started at all for a client that consumes neither: the read is ~11 s on a home
      // with many orgs, and for Gather it fed nothing (whitelabel/provisioning.ts).
      const wantsManaged = Boolean(relyingApp?.paymentConfig) || provisionsCommunityMessaging(enroll.aud);
      const managedPromise: Promise<Awaited<ReturnType<typeof listManagedAgents>>> = token && wantsManaged
        ? listManagedAgents(token).catch((e) => {
            console.warn('[connect] listManagedAgents failed (projection unavailable):', e);
            return [] as Awaited<ReturnType<typeof listManagedAgents>>;
          })
        : Promise.resolve([] as Awaited<ReturnType<typeof listManagedAgents>>);

      /*
        P4 — WORKSPACE MEMBERSHIP, two ceremonies around one stash (/connect/workspace-invite).
        Each is a side-effect on the way into an ORDINARY site-login: the relying app still gets
        its session code back, which is how it learns the ceremony finished.

        invite: the CUSTODIAN signs `workspace → member` with the same root credential that owns
        the workspace agent, and stashes it for the named member. Granting is the custodian's act;
        nothing here touches the member's own agent tree.
        join:   the MEMBER claims their stash (single use) and writes their OWN related-agent link
        carrying the grant — the only party the link endpoint permits. The workspace roster still
        gates every relying-app call; this link is reach, not authority.

        AND THE MEMBERSHIP IS THE GOVERNOR'S (2026-10-02, the owner's rule; `lib/workspace-governor.ts`).
        A workspace agent is a service that coordinates a workspace and holds no members, so when the
        workspace has a governing organization the invite ALSO invites into that organization — the org→member
        access grant, the role word and the organization's signed half of the has-member credential, exactly
        what `/connect/org-invite/agent` records, steward-gated on this person's stewardship of the governor —
        and the join records the membership THERE: the organization's own `org.membership:member:<sa>`, the
        member's OrganizationMembership naming the governor, the countersigned credential. The workspace's own
        wires are still signed and still ride the link, because the member needs to READ the workspace's vault;
        the link hangs under the governor. A LEGACY workspace (no governor) is invited into and joined exactly as
        before, and `resolveWorkspaceGovernor` says so once in the console.
      */
      if (enroll.template === 'workspace-member-invite') {
        if (!enroll.grantOrg || !enroll.member) return fail('This invitation names no workspace or member.');
        if (!token) return fail('Your Home session is needed to invite into a workspace.');
        const governed = await resolveWorkspaceGovernor(token, enroll.grantOrg, home.address);
        // A LEGACY WORKSPACE IS REFUSED HERE, NOT AT THE FAR END. The server records membership on organizations
        // only, so an invitation into a workspace with no governor is one nobody can accept; stashing it would
        // fail the invitee later, with no mention of why. The host is told what to set up, in the words every
        // screen about this uses.
        if (!governed) return fail(LEGACY_WORKSPACE_MESSAGE);
        // THE ROLE THIS INVITATION OFFERS (spec 427) — what the invitee will DO, as the organization's own definition.
        // A parameter that arrived but did not parse is refused outright: an invitation that was meant to carry a
        // role and silently carried none would tell the host one thing and the invitee another.
        if (enroll.roleOfferRaw && !enroll.roleOffer) return fail('This invitation names a role the Home could not read — nothing was sent. Invite again from the app.');
        const roleOffer = enroll.roleOffer ?? null;
        const roleSlug = roleOffer ? roleSlugOf(roleOffer.roleDefinitionId) : '';
        // A TEAM-SCOPED ROLE IS HELD ON THE TEAM. A team is an organization and holds its own members; the governor
        // redirect above exists only because a `.workspace` agent is a service with none. So a team role needs
        // `grant_org` to BE a team — decided from the agent's TYPE as this person's own tree records it, never from
        // the offer's word: a `scope: 'team'` naming a workspace must not produce an invitation into a service.
        let teamInvite = false;
        if (roleOffer?.scope === 'team') {
          const tree = (await fetch('/connect/related-orgs', { headers: { authorization: `Bearer ${token}` } }).then((r) => r.json()).catch(() => ({}))) as { orgs?: Array<{ orgAgent?: string; kind?: string }> };
          const kind = (tree.orgs ?? []).find((r) => (r.orgAgent ?? '').toLowerCase() === enroll.grantOrg!.toLowerCase())?.kind?.toLowerCase() ?? '';
          if (!TEAM_CLASS.has(kind)) return fail(`"${roleOffer.name}" is a role held on a team, and this invitation is not into one — nothing was sent.`);
          teamInvite = true;
        }
        const total = teamInvite ? 4 : 3;
        let governorAccess: DelegationWire | null = null;
        let relationshipOffer: RelationshipOfferV1 | null = null;
        let teamAccess: DelegationWire | null = null;
        let teamRelationshipOffer: RelationshipOfferV1 | null = null;
        {
          setGrantProgress({ step: 1, total, label: `Inviting them into ${governed.governorName || 'the organization'}…` });
          // Signed AS THE ORGANIZATION — its custody is this person's credential, reached the way select-existing
          // reaches an org it stewards — so both artifacts validate by the organization's ERC-1271.
          const signAsOrg = await signHashFor(viaLower as Via, governed.governor, auth);
          governorAccess = toWire(await issueOrganizationResourceAccessDelegation(governed.governor, enroll.member, MCP_SERVER_ID, signAsOrg));
          // An ORGANIZATION-scoped role is the governor's to offer, and rides this invitation; a team's rides the
          // team's own, below. The credential's terms name the role's word; the access is the wire beside it.
          const orgScoped = roleOffer?.scope === 'organization' ? roleOffer : null;
          relationshipOffer = await offerRelationshipCredential({ kind: 'has-member', subject: enroll.member, object: governed.governor, terms: { role: orgScoped ? roleSlug : 'member' }, signAsObject: signAsOrg });
          const inv = await fetch('/connect/org-invite/agent', {
            method: 'POST',
            headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
            body: JSON.stringify({ org: governed.governor, agent: enroll.member, memberAccessDelegation: governorAccess, role: 'member', relationshipOffer, ...(orgScoped ? { orgRole: orgScoped } : {}) }),
          });
          const invOut = (await inv.json().catch(() => ({}))) as { ok?: boolean; error?: string };
          // An invitation the organization cannot record admits nobody — the same refusal `/org-invite` makes.
          if (!inv.ok || invOut.ok === false) return fail(invOut.error ?? `${governed.governorName || 'the organization'} could not record the invitation (HTTP ${inv.status})`);
        }
        if (teamInvite && roleOffer) {
          // THE TEAM INVITES TOO — exactly what the governor just did, signed AS THE TEAM by the same steward
          // credential: the team→member access grant, the team's half of the has-member credential, and the role.
          // The governor's invitation above is unchanged: somebody on a team also belongs to the organization.
          // A team that cannot record it (its storage is not enabled, or this person does not steward it) FAILS the
          // invitation here, by name — a role that was offered and landed nowhere is the one outcome not allowed.
          setGrantProgress({ step: 2, total, label: `Inviting them onto ${enroll.orgBase?.trim() || 'the team'} as ${roleOffer.name}…` });
          const signAsTeam = await signHashFor(viaLower as Via, enroll.grantOrg, auth);
          // THE TEAM'S GRANT TO ITS MEMBER IS THE ONE THEY READ THE TEAM WITH — the record-covering wire (the team's
          // catalog and artifacts, its directory and board index), not the profile-only grant an organization gives a
          // member of the governor above. A relying app presents a member's ACCESS grant for their reads; a team
          // invitation that stored the narrow one gave the new coach an empty roster on the team they had just joined
          // (walked live, 2026-10-05). One wire, signed as the team, for the invitation and for the link.
          teamAccess = toWire(await issueWorkspaceMembershipAccessDelegation(enroll.grantOrg, enroll.member, MCP_SERVER_ID, signAsTeam));
          teamRelationshipOffer = await offerRelationshipCredential({ kind: 'has-member', subject: enroll.member, object: enroll.grantOrg, terms: { role: roleSlug }, signAsObject: signAsTeam });
          const tinv = await fetch('/connect/org-invite/agent', {
            method: 'POST',
            headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
            body: JSON.stringify({ org: enroll.grantOrg, agent: enroll.member, memberAccessDelegation: teamAccess, role: 'member', relationshipOffer: teamRelationshipOffer, orgRole: roleOffer }),
          });
          const tout = (await tinv.json().catch(() => ({}))) as { ok?: boolean; error?: string };
          if (!tinv.ok || tout.ok === false) return fail(`${enroll.orgBase?.trim() || 'The team'} could not record the invitation as ${roleOffer.name}: ${tout.error ?? `HTTP ${tinv.status}`}. Nothing further was sent — invite again without a role, or enable the team's storage first.`);
        }
        setGrantProgress({ step: teamInvite ? 3 : 2, total, label: 'Signing the member’s access…' });
        const signHash = await signHashFor(viaLower as Via, home.address, auth);
        const grant = await issueSiteDelegation(enroll.grantOrg, enroll.member, signHash);
        // P4 record coverage: the site delegation is reach; the MEMBERSHIP wire is what lets the
        // member READ the workspace/team's records (member plane + library, where every field
        // artifact lives). Same shape the operator seeds mint — record scope, no allowedTargets.
        const membership = await issueWorkspaceMembershipAccessDelegation(enroll.grantOrg, enroll.member, MCP_SERVER_ID, signHash);
        const res = await fetch('/connect/workspace-invite', {
          method: 'POST',
          headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
          body: JSON.stringify({
            workspace: enroll.grantOrg,
            member: enroll.member,
            delegation: toWire(grant),
            membership: toWire(membership),
            workspaceName: enroll.orgBase ?? '',
            governor: governed.governor, governorName: governed.governorName, governorAccess, relationshipOffer,
            ...(teamAccess ? { teamAccess, teamRelationshipOffer, teamRoleName: roleOffer?.name ?? '' } : {}),
          }),
        });
        const out = (await res.json().catch(() => ({}))) as { ok?: boolean; error?: string };
        if (!res.ok || !out.ok) return fail(out.error ?? `the invitation could not be stored (HTTP ${res.status})`);
        // AND TELL THEM. The stash is claimed by a ceremony the member starts from the app; nothing at their
        // own Home said an invitation existed — a host "invited Rich" and Rich's Home showed nothing waiting
        // (2026-09-13). So the host's own agent sends them one message, the way an organization's invitation
        // reaches an invitee (spec 341 §5.1b): delivered over A2A by the inviter's agent, never written by the
        // Home, carrying the app's link to where the join is. Best-effort: the invitation stands on the stash.
        setGrantProgress({ step: total, total, label: 'Telling them…' });
        try {
          const { approveMessagingContact, COMMUNITY_MESSAGING_VALIDITY_SECONDS } = await import('../../lib/messaging-ceremony');
          const { sendMessage } = await import('../../lib/messaging-send');
          setSsoCookie(token, viaLower); // `sendMessage` reads the person's bearer from where the Home keeps it
          await approveMessagingContact({ person: home.address, recipient: enroll.member, via: viaLower as Via, token, validitySeconds: COMMUNITY_MESSAGING_VALIDITY_SECONDS });
          const place = enroll.orgBase?.trim() || 'a workspace';
          await sendMessage({
            person: home.address,
            recipient: enroll.member,
            bodyText: `${homeLabel(home.name)} invited you into ${place} at ${appName}${roleOffer ? ` as ${roleOffer.name}` : ''}. Open ${place}'s page there and press "Join at your Home" — your Home will then know you as a member.`,
            contextRefs: enroll.appLink ? [{ kind: 'app-link', id: enroll.appLink, label: `Join ${place} at ${appName}` }] : [],
          });
        } catch (e) {
          console.warn('[connect] workspace-member-invite: the invitation could not be sent as a message', e);
        }
      }
      if (enroll.template === 'workspace-join') {
        if (!enroll.grantOrg) return fail('This join names no workspace.');
        if (!token) return fail('Your Home session is needed to join a workspace.');
        const tJoin = Date.now();
        const lapJoin = (what: string) => console.info(`[workspace-join] ${what} +${Date.now() - tJoin}ms`);
        setGrantProgress({ step: 1, total: 2, label: 'Claiming your invitation…' });
        const res = await fetch('/connect/workspace-invite', {
          method: 'POST',
          headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
          body: JSON.stringify({ workspace: enroll.grantOrg, claim: true }),
        });
        const out = (await res.json().catch(() => ({}))) as {
          ok?: boolean;
          error?: string;
          invite?: {
            delegation?: unknown; membership?: unknown; workspaceName?: string;
            governor?: string; governorName?: string; governorAccess?: { delegate?: string } | null; relationshipOffer?: unknown;
            /** Spec 427 — the invitation was into a TEAM and offered a role: the team's own grant and credential half. */
            teamAccess?: { delegate?: string } | null; teamRelationshipOffer?: unknown; teamRoleName?: string;
          };
        };
        if (!res.ok || !out.ok || !out.invite?.delegation) {
          return fail(out.error ?? 'No invitation was found for you at this workspace — ask its steward to invite you.');
        }
        lapJoin('invitation claimed');
        const invite = out.invite;
        const governor = typeof invite.governor === 'string' && /^0x[0-9a-fA-F]{40}$/.test(invite.governor) ? (invite.governor.toLowerCase() as Address) : null;
        const signHash = await signHashFor(viaLower as Via, home.address, token ? { token } : undefined);
        // THE MEMBER'S OWN LINK TO THE WORKSPACE. `siteDelegation` is the workspace's site grant — REACH, and
        // nothing else. It was sent as `stewardshipDelegation` until 2026-10-02, and a site grant has exactly the
        // caveat shape a stewardship wire has (governance targets, no record scope), so every member of every
        // workspace verified as its STEWARD: `act-as` in the field app, the invite and remove gates here. A member
        // must never come out as a steward, whichever branch below wrote the link.
        const linkBody = {
          person: home.address,
          orgAgent: enroll.grantOrg,
          orgName: invite.workspaceName || enroll.orgBase || 'Field Workspace',
          // The org's purpose IS the kind of this link (related-orgs maps it back): a join into a
          // field TEAM under a hard-coded 'field-workspace' listed the team as one of the person's
          // workspaces (2026-08-30). The app says what it is in `org_purpose`; default stays workspace.
          purpose: enroll.purpose ?? 'field-workspace',
          requestedBy: enroll.aud,
          kind:
            enroll.purpose === 'field-team' ? 'team'
            : enroll.purpose === 'field-circle' ? 'circle'
            : enroll.purpose === 'field-church' ? 'church'
            : 'workspace',
          // Under the GOVERNOR when there is one: a workspace hangs under the organization that governs it.
          parent: governor ?? home.address,
          relationship: 'member',
          siteDelegation: invite.delegation,
          // The record-covering wire (P4): `scopedWireFor` reads this off the link, the library
          // org-read presents it as scopedAccess, and the DO evaluates its scope per resource.
          membershipDelegation: invite.membership ?? null,
          ...(governor ? { governor } : {}),
        };
        const linkWorkspace = async (): Promise<void> => {
          const linked = await fetch('/connect/related-orgs', {
            method: 'POST',
            headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
            body: JSON.stringify(linkBody),
          });
          const link = (await linked.json().catch(() => ({}))) as { ok?: boolean; error?: string };
          if (!linked.ok || link.ok === false) {
            throw new Error(link.error ?? `joined, but the workspace could not be linked to your home (HTTP ${linked.status})`);
          }
        };
        const { recordOrgMembership } = await import('../../lib/org-membership');
        if (governor) {
          // THE MEMBERSHIP IS THE ORGANIZATION'S, and it goes first: `recordOrgMembership` writes the person's link
          // to the governor, and the workspace link below hangs UNDER the governor, which the link store refuses
          // until that link exists. Nothing is recorded on the workspace itself. The two-sided has-member credential
          // (spec 410 §8) is countersigned INSIDE `recordOrgMembership` from the offer it is handed — the
          // organization signed its half at the invitation.
          setGrantProgress({ step: 2, total: 3, label: `Joining ${invite.governorName || 'the organization'}…` });
          await recordOrgMembership(home.address, governor, signHash, token, invite.governorAccess ?? null, homeLabel(home.name), relationshipOfferOf(invite.relationshipOffer));
          lapJoin('organization recorded the membership');
          // AND THE TEAM'S OWN MEMBERSHIP, when the invitation was into a team and offered a role (spec 427): a team is
          // an organization and holds its own members. The team's object stamps the role from ITS invitation record.
          // BEFORE the link below, on purpose: `recordOrgMembership` writes this person's link to the team as a plain
          // member link, and the link write that follows is the one that must stand — it carries the record-covering
          // wire the member reads the team's vault with.
          if (invite.teamAccess && enroll.grantOrg.toLowerCase() !== governor) {
            setGrantProgress({ step: 2, total: 3, label: `Joining the team${invite.teamRoleName ? ` as ${invite.teamRoleName}` : ''}…` });
            await recordOrgMembership(home.address, enroll.grantOrg, signHash, token, invite.teamAccess, homeLabel(home.name), relationshipOfferOf(invite.teamRelationshipOffer));
            lapJoin('team recorded the membership');
          }
          setGrantProgress({ step: 3, total: 3, label: 'Adding the workspace to where you can work…' });
          try { await linkWorkspace(); } catch (e) { return fail(e instanceof Error ? e.message : String(e)); }
          lapJoin('linked');
        } else {
          // A LEGACY WORKSPACE (the invitation names no governor) CANNOT BE JOINED. The server records membership on
          // organizations only, so the workspace's own record — the roster the relying app reads — would never be
          // written, and the person would be told they had joined a club that does not list them. The refusal is
          // made here, in words that say what the host has to do, rather than in a warning nobody reads.
          return fail(LEGACY_WORKSPACE_MESSAGE);
        }
      }

      let code: string;
      // Set by the plain sign-in branch alone. The vault-key leg below is shared with every template,
      // and each of those already narrates itself — so the final step is only ours to name when the
      // sign-in branch did the narrating.
      let narratedSignIn = false;
      if (enroll.template === 'person-create') {
        /**
         * ANOTHER PERSON OF YOUR OWN, asked for by a relying app (spec: ap:DefaultPersonChoice).
         *
         * Somebody takes a name inside an app — a character in a game, a handle in a community — and that
         * name becomes an agent of theirs: person-class, `.me`-named, custodied by the same credential,
         * with a vault of its own so what it learns is ITS memory rather than a smear across their own.
         *
         * IT IS NEVER THE DEFAULT. Their own name stays the one their Home opens as; this one is somebody
         * they can switch to. Chartering a person must not quietly change who you are when you sign in.
         *
         * IDEMPOTENT BY LABEL, which is the whole point of doing it this way. The second game asks for the
         * same name and gets the same agent — the character comes back with everything it knew — rather than
         * a twin with an empty vault. A label that resolves to somebody ELSE'S agent is refused rather than
         * joined: names are global, and two people cannot be the same character.
         */
        const label = (enroll.orgBase ?? '').trim();
        if (label.length < 3) return fail('Name this person — at least 3 characters.');
        if (!token) return fail('Your Home session is needed to add another person.');
        const already = await resolveHomeNameForLabel(label);
        let personAgent: Address;
        let personName: string;
        if (already) {
          const mine = await listManagedAgents(token).catch(() => []);
          if (!mine.some((m) => m.agent.toLowerCase() === already.agent.toLowerCase())) {
            return fail(`“${label}” is already somebody else’s name.`);
          }
          personAgent = already.agent;
          personName = already.name;
        } else {
          const created = await createManagedAgent(
            { kind: 'person', label, parent: home.address, person: home.address, via: viaLower },
            token,
            (st) => setGrantProgress({ step: 1, total: 2, label: st }),
          );
          if (!created.ok) return fail(created.error);
          personAgent = created.result.agent;
          personName = created.result.name;
          // A PERSON OF YOURS HAS A VAULT OF THEIR OWN, and it is required rather than best-effort: what
          // this person learns is the reason they exist, and one that cannot remember is a name with
          // nothing behind it.
          setGrantProgress({ step: 2, total: 2, label: 'Giving them somewhere to remember…' });
          const bound = await activateVaultIfNeeded(personAgent, viaLower as Via, auth);
          if (!bound.ok) return fail(bound.error);
          const delivery = await activateInboxDeliveryIfNeeded(personAgent, viaLower as Via, auth);
          if (!delivery.ok) console.warn('[person-create] delivery grant not provisioned:', delivery.error);
          const ix = await activateInteractionsIfNeeded(personAgent, viaLower as Via, auth);
          if (!ix.ok) console.warn('[person-create] interactions grant not provisioned:', ix.error);
        }
        const proved = await personGrantForOrgCreate(home, delegate, viaLower, auth, {
          org: {
            orgAgent: personAgent,
            orgName: personName,
            kind: 'person',
            purpose: enroll.purpose ?? 'persona',
            person: home.address,
            // NEITHER STEWARDED NOR A MEMBERSHIP: it is them, under another name.
            relationship: 'self',
          },
          // No stewardship delegation: you do not oversee yourself. An organization signs one to its
          // steward because it has no session of its own; another person of yours has one — theirs.
          grant: undefined,
        }, enroll.sessionKey);
        if (!proved.ok) return fail(proved.error);
        code = await submitEnrollGrant(grant_id, proved.grant, proved.org, proved.sessionDelegation);
      } else if (enroll.template === 'workspace-create') {
        const name = (enroll.orgBase ?? orgSel?.orgName ?? '').trim();
        if (name.length < 3) return fail('Name this field workspace — at least 3 characters.');
        if (!token) return fail('Your Home session is needed to create a workspace.');
        // THE ORGANIZATION FIRST, THEN THE WORKSPACE UNDER IT (`createGovernedWorkspace`): a workspace agent is a
        // service and holds no members, so the name the app asked for charters `<name>.org` — the governor, by
        // org-create's own road — and `<name>.workspace` chartered under it, stewarded by this person. The token's
        // `org` payload is still the workspace's, with the governor beside it.
        const created = await createGovernedWorkspace(home, name, delegate, viaLower as Via, auth, {
          purpose: enroll.purpose ?? 'field-workspace',
          requestedBy: enroll.aud,
          grantOrg: enroll.grantOrg,
          onProgress: setGrantProgress,
        });
        if (!created.ok) return fail(created.error);
        const proved = await personGrantForOrgCreate(home, delegate, viaLower, auth, created, enroll.sessionKey);
        if (!proved.ok) return fail(proved.error);
        code = await submitEnrollGrant(grant_id, proved.grant, proved.org, proved.sessionDelegation);
      } else if (enroll.template === 'org-create') {
        // ORG-CREATE for a RECOGNIZED member (e.g. a facilitator org for demo-jp). This component is
        // reached for a NAMELESS enroll (spec 257 §11) — including org-create — but previously ran ONLY
        // the site-login pipeline below, submitting `org=undefined`. The relying app's /token then
        // returned no org → demo-jp threw "no organization returned from your home" even though the
        // request WAS an org-create (no org was ever deployed). Deploy the org custodied by this member
        // and submit the grant WITH the org payload (KMS → bootstrap-org; the descriptor build is
        // non-fatal per #295). One mechanism, no fallback (ADR-0013). Gated by TEMPLATE, not org_base:
        // a chooser-mode request carries no org_base — the choose-org step above resolved `orgSel`.
        // The person's chooser pick wins over the URL: choosing an EXISTING org while the app
        // suggested a new name must grant from that org, not deploy the suggestion anyway.
        const orgBase = orgSel?.orgName ?? enroll.orgBase;
        const existingOrg = orgSel?.existingOrg ?? enroll.existingOrg;
        // SELECT-EXISTING CARRIES NO NAME. `existing_org` names the organization by ADDRESS and
        // deploys nothing — there is no name to claim, which is the whole point — so requiring
        // `orgBase` refused every select-existing request from the recognized path with "No
        // organization was chosen" while the chosen organization sat in the URL. `createOrganization`
        // handles the existing branch first and uses `base` only as the link's display name.
        if (!orgBase && !existingOrg) return fail('No organization was chosen for this request.');
        const created = await createOrganization(
          home,
          orgBase ?? '',
          delegate,
          viaLower,
          auth,
          {
            purpose: enroll.purpose,
            requestedBy: enroll.aud,
            grantOrg: enroll.grantOrg,
            existingOrg,
            signAsOrg: orgSel?.asSteward,
            onProgress: setGrantProgress,
          },
        );
        if (!created.ok) return fail(created.error);
        // THE MISSION REGISTRY (a relying app's kit-built registry, `missionRegistryConfig`): an org-create that
        // carries `registry_entry` is not done when the org exists — it ends with the org LISTED. The steward
        // signs the covenant as themselves; the org signs its own entry; both prompts are this one ceremony.
        {
          const regAuth: Auth | undefined = token ? { token } : undefined;
          const listed = await withMissionRegistry({ enroll, relyingApp, org: created.org, steward: home.address, via: viaLower, auth: regAuth, signHashFor: (v, s, a) => signHashFor(v as Via, s, a), onStep: (label) => setGrantProgress({ step: 2, total: 3, label }) });
          if (!listed.ok) return fail(listed.error);
          created.org = listed.org;
        }
        // A TEAM is usable from the first approval or it is not created — the same storage trio
        // workspace-create runs (a team's own roster lives in its own vault). Scoped to field-team
        // and to a FRESH deploy: associating an existing org changes nothing about its storage.
        const freshTeamAgent =
          (enroll.purpose === 'field-team' || enroll.purpose === 'field-circle' || enroll.purpose === 'field-church') && !enroll.existingOrg && !orgSel?.existingOrg
            ? ((created.org as { orgAgent?: string }).orgAgent as Address | undefined)
            : undefined;
        if (freshTeamAgent) {
          setGrantProgress({ step: 2, total: 2, label: 'Enabling the team’s storage…' });
          const bound = await activateVaultIfNeeded(freshTeamAgent, viaLower as Via, auth);
          if (!bound.ok) return fail(bound.error);
          const delivery = await activateInboxDeliveryIfNeeded(freshTeamAgent, viaLower as Via, auth);
          if (!delivery.ok) console.warn('[team-create] delivery grant not provisioned:', delivery.error);
          const ix = await activateInteractionsIfNeeded(freshTeamAgent, viaLower as Via, auth, false, ORG_INTERACTIONS_SESSION_LEAF_TTL_SECONDS);
          if (!ix.ok) console.warn('[team-create] interactions grant not provisioned:', ix.error);
        }
        const proved = await personGrantForOrgCreate(home, delegate, viaLower, auth, created, enroll.sessionKey);
        if (!proved.ok) return fail(proved.error);
        code = await submitEnrollGrant(grant_id, proved.grant, proved.org, proved.sessionDelegation);
      } else {
        // SITE-LOGIN — spec 270 v4 W2: sign + carry the DEL-001 leaf for the relying app's session key.
        // spec 272/243 — x402-pay: a recognized member already has a home session `token` in hand, so
        // resolve their PRE-CREATED person-treasury (approach A) and authorize a capped `treasury →
        // lbsb-treasury` payment delegation in the SAME ceremony. No treasury → connect without payment.
        // Derived from `givePermission` rather than restated, so a new field on the payment leg (the
        // `redeemer` this connect needs) cannot be added in one of the three connect surfaces and
        // silently dropped in the other two.
        let payment: Parameters<typeof givePermission>[5];
        const pc = relyingApp?.paymentConfig;
        // Resolve the member's PRE-CREATED person-treasury only for apps that declare financial ops
        // (a paymentConfig). Surfaced to the relying app as `treasury` so it can gate them up front —
        // a member with no treasury is told to create one, not shown a Buy-access flow that silently
        // no-ops. Apps with no paymentConfig have no financial ops, so the connect skips the lookup.
        let treasuryAddr: Address | null = null;
        if (pc) {
          // The projection is re-read here, AFTER the new-member setup screen has run: a member who
          // just had an account opened for them is in it (the create invalidates the shared read),
          // which is what lets the spend mandate below name the account they were given moments ago.
          treasuryAddr = ((await managedPromise).find((a) => a.kind === 'person-treasury')?.agent as Address) ?? null;
          // Projection miss → reconcile from the authoritative naming registry (`<label>-treasury.<tld>`).
          if (!treasuryAddr) {
            treasuryAddr = await resolveTreasuryByConvention(home.name);
            if (treasuryAddr) console.warn('[connect] person-treasury reconciled from ANS (projection was stale):', treasuryAddr);
          }
        }
        // ALL custodians (wallet / passkey / social-KMS) — the charge is signed via signHashFor, which
        // handles every credential. With no treasury we connect without payment and the app surfaces
        // "create a treasury" rather than attempting a charge.
        if (isPaymentTemplate(enroll.template) && pc && treasuryAddr) {
          // spec 272 — charge the tier amount the relying app requested (enroll.payAmount), CAPPED by the
          // client's registered per-charge max. Defaults to the max (≈ pay-as-you-go) when unspecified.
          const cap = BigInt(pc.maxAmountPerCharge);
          const req = enroll.payAmount ? BigInt(enroll.payAmount) : cap;
          const amt = req < cap ? req : cap;
          payment = {
            treasury: treasuryAddr,
            payee: pc.payee,
            asset: pc.asset,
            maxAmountPerCharge: BigInt(pc.maxAmountPerCharge),
            maxAggregate: BigInt(pc.maxAggregate),
            maxRedemptionsPerWindow: pc.maxRedemptionsPerWindow,
            windowSeconds: pc.windowSeconds,
            mode: pc.mode,
            // CHARGE the first payment in this ceremony (all-custodian) → settlementHash → app mints a pass.
            chargeNow: true,
            chargeAmount: amt,
            edition: 'lbsb',
            // spec 272 recurring — a SUBSCRIPTION connect (sub_period set): also mint a standing pull mandate.
            subscription: enroll.subPeriod ? { periodSeconds: enroll.subPeriod } : undefined,
          };
        } else if (grantsCoinAtConnect(relyingApp) && plainSignIn) {
          // THE APP'S OWN COIN, granted in the PLAIN sign-in (`new_member.currency.spend_grant`).
          // Same mandate, same `issuePaymentDelegation`, same return trip to the app on the token
          // exchange — the only thing that changed is that the member no longer has to come back for
          // a second ceremony to authorize it. `null` (no account, or no currency declared) simply
          // leaves `payment` undefined and the connect runs exactly as it did before.
          // THE PLAIN SIGN-IN ONLY. A ceremony template (charter a club, invite a member into it, join
          // it, hire a coach) is a different act, and the sheet for it said "take up to 200 Sheqels
          // from your money account" beside "let the person you named read this workspace" — a spending
          // mandate re-minted, and disclosed, on the one screen whose job is to say what is being trusted.
          payment = coinMandateLeg(relyingApp, treasuryAddr) ?? undefined;
        }
        // spec 345 — a self-vault grant rides this SAME plain sign-in when the client declares one.
        const selfVaultScope = whitelabel.relyingApps.find((a) => a.client_id === enroll.aud)?.self_vault_grant;
        lapCeremony('template leg done');
        const reuse = { reuseWithSelfVault: reusesStandingGrantWithSelfVault(enroll.aud) };
        // Say what is happening. This branch used to run from Allow to done — a sponsored userOp, two
        // on-chain verifications with retry ladders, a vault bind — under one frozen 'Starting…', which
        // is the longest silence in the product. Same legs, narrated.
        narratedSignIn = true;
        setGrantProgress({ step: 1, total: 3, label: 'Signing your permission…' });
        let granted = await givePermission(home, delegate, viaLower, auth, enroll.sessionKey, payment, selfVaultScope, reuse);
        if (!granted.ok) return fail(granted.error);
        lapCeremony(`permission given${granted.reused ? ' (reused)' : ''}`);
        setGrantProgress({ step: 2, total: 3, label: 'Confirming it on the chain…' });
        try {
          code = await submitEnrollGrant(grant_id, granted.grant, undefined, granted.sessionDelegation, granted.paymentDelegation, granted.settlementHash, treasuryAddr, granted.pullDelegation, granted.selfVaultGrant);
          lapCeremony('code minted');
        } catch (e) {
          // The REUSED standing grant was refused (revoked / no longer verifiable). Clear it and mint
          // fresh ONCE — the single explicit fallback (ADR-0013). A fresh-mint refusal is terminal.
          if (!granted.reused) throw e;
          console.warn('[connect] standing grant refused — clearing cache and minting fresh:', e);
          clearStandingGrant(home.address, delegate);
          granted = await givePermission(home, delegate, viaLower, auth, enroll.sessionKey, payment, selfVaultScope, reuse);
          if (!granted.ok) return fail(granted.error);
          code = await submitEnrollGrant(grant_id, granted.grant, undefined, granted.sessionDelegation, granted.paymentDelegation, granted.settlementHash, treasuryAddr, granted.pullDelegation, granted.selfVaultGrant);
        }
      }
      if (narratedSignIn) setGrantProgress({ step: 3, total: 3, label: 'Enabling your storage…' });
      // spec 278 — bind the member's per-person vault key during connect, for EVERY custody type. A
      // relying-app-first member (connects here, never runs the full journey / the /vault-key portal) would
      // otherwise have NO binding, so their first vault read/write at the relying app fails closed with
      // vault_key_unauthorized. KMS (social) signs server-side (no gesture); wallet/passkey sign their own
      // VaultKeyAuthorization on-device — ONE extra signature at connect (the deliberate "custodian backs all
      // authority" tradeoff). Idempotent (skipped if already bound) + best-effort (a vault hiccup never blocks
      // the connect — the delegation is already minted, and /vault-key + the journey remain as a re-bind path).
      // Same reason: the vault-key ceremony signs, so a wallet-credential demo home needs the token.
      try { await activateVaultIfNeeded(home.address, viaLower, token ? { token } : undefined); }
      catch (e) { console.warn('[connect] vault-key activation failed (non-fatal — vault reads will 401 until bound):', e); }
      lapCeremony('vault key checked');
      // Same consent as connect: storage, delivery, and a SCOPED wire — the communities they belong
      // to plus, for a named home, the named-to-named class — so the first send from the app is not
      // a second ceremony. One signature; the gate resolves membership and namedness live.
      if (token && provisionsCommunityMessaging(enroll.aud) && (enroll.template === 'site-login' || enroll.aud === 'commons-app')) {
        try {
          const named = !!home.name?.trim();
          // Site-login reuses the projection read started before the grant leg — one fetch, not two.
          // An org-create just deployed a NEW org, so it must re-read the projection instead.
          const managed = enroll.template === 'site-login' ? await managedPromise : await listManagedAgents(token);
          const orgs = managed.filter((a) => agentClassOf(a.kind) === 'org');
          if (orgs.length === 0) {
            await provisionCommunityMessaging({ person: home.address, named, via: viaLower, token });
          }
          for (const o of orgs) {
            await provisionCommunityMessaging({
              person: home.address,
              org: o.agent,
              named,
              via: viaLower,
              token,
            });
          }
        } catch (e) {
          console.warn('[connect] community messaging provision failed (non-fatal):', e);
        }
      }
      // spec 280 carve-out — self-heal the published connection KIND on every successful social connect
      // (idempotent, gasless, kind-only) so a named social home stops being EOA-ambiguous at re-entry.
      if (isKmsVia(viaLower)) void publishSocialConnectionKindIfNeeded(home.address, home.name, viaLower, { token });
      // Refresh the cross-subdomain session + FedCM signal (the member is still signed in here).
      setSsoCookie(token, viaLower);
      setFedcmLoginStatus('logged-in');
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
      // Long enough for the "connected" receipt to paint; the popup lingering is dead time the
      // member reads as a hang, so keep it short.
      setTimeout(() => deliverEnrollCode(enroll, api.popupMode, code), 400);
    } catch (e) {
      fail(e);
    }
  }

  function onDecline() {
    if (enroll) deliverEnrollCode(enroll, api.popupMode, ''); // empty code → relying app treats as cancel
  }

  if (!enroll) return null;

  if (phase === 'resolving') {
    return (
      <Shell>
        <div className="onboarding-busy">
          <WorkingBar />
          <span className="spinner spinner-lg" role="status" aria-label="Recognizing you" />
          <p className="onboarding-busy-msg">Welcome back — getting your home…</p>
        </div>
      </Shell>
    );
  }

  if (phase === 'choose-org') {
    return (
      <Shell>
        <OrgChooser
          token={token}
          appHost={appHost}
          purpose={enroll?.purpose}
          defaultName={enroll?.orgBase}
          hideHandles={hideIds}
          onChoose={(c) => { setOrgSel(c); setPhase('consent'); }}
          onDecline={onDecline}
        />
      </Shell>
    );
  }

  if (phase === 'granting') {
    return (
      <Shell>
        <CeremonyProgress
          label={clientProgressText(relyingApp, grantProgress.label)}
          hint={clientProgressText(relyingApp, grantProgress.hint ?? `This is how ${appName} gets a scoped, revocable grant — never custody.`)}
          step={grantProgress.step}
          total={grantProgress.total}
        />
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

  // consent — recognized; one tap to authorize as yourself (no re-login).
  // spec: `profile` scope — an app registered to receive the member's human name says so HERE, in
  // the same list as everything else it can do. The setup screen discloses it to a member who is
  // typing the name now; this is what a RETURNING member (whose name is already on file, and who
  // never sees that screen) gets to read before authorizing. No-op for every unscoped app.
  const baseTpl = withEmailClaimConsent(
    withProfileNameConsent(
      whitelabel.delegationTemplates[enroll.template] ?? {
        canDo: [],
        cannotDo: ['Move your funds', 'Add sign-in methods', 'Change your recovery'],
      },
      relyingApp,
    ),
    relyingApp,
  );
  // The coin's consent lines belong to the plain sign-in, where the coin is granted (see the mandate leg).
  // Last: the client's OWN wording for this template, when it registered one (no-op for every other app).
  const tpl = withClientConsent(plainSignIn ? withCurrencyConsent(baseTpl, relyingApp, appName) : baseTpl, relyingApp, enroll.template);
  return (
    <div className="onboarding-screen">
      <div className="onboarding-card wide">
        {enroll.template === 'org-create' && (enroll.orgBase ?? orgSel?.orgName) && (
          <p className="onboarding-sub">
            Organization: <strong>{clientOrgName(relyingApp, (enroll.orgBase ?? orgSel?.orgName)!)}</strong>
            {(enroll.existingOrg ?? orgSel?.existingOrg) ? ' — existing; no new org is created.' : ' — new.'}
          </p>
        )}
        {enroll.template === 'org-create' && enroll.registryEntry && relyingApp?.missionRegistryConfig && (
          <p className="onboarding-sub">
            Then it is listed in {appName}’s mission registry: you sign the covenant as yourself, and the organization signs its own entry — one year, renewable, revocable.
          </p>
        )}
        {enroll.template === 'act-as-me' && home?.address && token && (
          <ActAsMeConsent token={token} agent={home.address} onChange={onActChoices} />
        )}
        <ConsentSheet
          title={fmt(c.authorizeStepTitle, { app: appName })}
          signedInAs={signedInAs}
          signedInBare={hideIds && !!home}
          appName={appName}
          appDomain={enroll.viaHost ? `through ${registeredName} · ${appDomain}` : appDomain}
          appLogo={relyingApp?.logo}
          appDescription={relyingApp?.description}
          template={tpl}
          authorizeLabel={fmt(c.authorizeStepCta, { app: appName })}
          onAuthorize={onAuthorize}
          onDecline={onDecline}
        />
        <button className="btn-ghost onboarding-secondary" onClick={() => { clearSsoCookie(); onUnrecognized(); }}>
          {switchAccountLabel(relyingApp, home?.name)}
        </button>
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
