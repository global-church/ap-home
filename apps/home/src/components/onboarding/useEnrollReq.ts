'use client';
// The OIDC relying-app enrollment contract — parsed once from the query, with the grant +
// code-delivery + popup mechanics. Moved VERBATIM from the old App.tsx (spec 230): the
// audit-F3 exact-origin postMessage, PKCE code_challenge passthrough, and popup-vs-redirect
// delivery are load-bearing — do not alter the wire behavior.
//
// SEC-005: the relying-origin allowlist is no longer hardcoded here. It's derived from
// `whitelabel.relyingApps[].redirect_uris` so the two sources cannot drift.
import { verifiedEmailFor } from '../../lib/verified-email';
import { parseRoleOffer, type RoleOfferV1 } from '../../lib/org-role';
import { checkOrgDisplayName, parseOrgTypeParam, type OrgTypeV1 } from '../../lib/org-type';

/** `role_offer` — base64url of the offer's JSON. An offer that does not parse is DROPPED WITH A WARNING here and the
 *  ceremony refuses to run with it (see RecognizedEnroll): a role nobody could record is not silently ignored. */
export function roleOfferFromParam(raw: string | null): { roleOffer?: RoleOfferV1; roleOfferRaw?: string } {
  if (!raw) return {};
  try {
    const bin = atob(raw.replace(/-/g, '+').replace(/_/g, '/'));
    const parsed = parseRoleOffer(JSON.parse(new TextDecoder().decode(Uint8Array.from(bin, (c) => c.charCodeAt(0)))));
    if (parsed.ok) return { roleOffer: parsed.offer, roleOfferRaw: raw };
    console.warn(`[connect] role_offer refused: ${parsed.error}`);
  } catch (e) { console.warn('[connect] role_offer could not be read', e); }
  return { roleOfferRaw: raw };
}

import { CLIENT_DEFAULTS, applyClientDefaults } from '../../lib/client-defaults';
import { isPaymentTemplate } from '../../whitelabel/config';
import { useCallback, useEffect, useState } from 'react';
import type { Address } from '@agenticprimitives/types';
// Curated clients resolve synchronously from the bundle; MEMBER-REGISTERED ones are looked up
// once via /connect/client-info and then answer synchronously too (src/lib/relying-clients.ts).
import { knownRelyingClient, primeRelyingClient, relyingOriginAllowed } from '../../lib/relying-clients';
import { writePendingEnroll } from './pending-enroll';
import { sharesProfileName } from '../../lib/new-member';
import { profileForConnect } from '../../lib/connect-profile-name';
import { sharesEmailClaim } from '../../whitelabel/provisioning';

export interface EnrollReq {
  aud: string; // = client_id
  redirectUri: string; // = redirect_uri (exact-match in the registry)
  state: string;
  name: string; // = agent_name — optional; empty = name-deferred Google connect (spec 257 §11)
  delegate: Address; // the relying site's delegate Smart Account (delegation recipient)
  nonce: string;
  codeChallenge: string; // PKCE S256 challenge
  template: string; // delegation_template: 'site-login' | 'org-create'
  orgBase?: string; // org_create: the org name to create
  purpose?: string; // org_create: app-level purpose tag (e.g. jp-adopter-org) — ADR-0025
  grantOrg?: Address; // org_create: a broker org SA to also grant scoped read (spec 246)
  member?: Address; // workspace-member-invite: the person SA being granted into the workspace (P4)
  /** workspace-member-invite (spec 427): the ROLE the invitation offers — a snapshot of the organization's own role
   *  definition (ids and words only; anything else on it is refused when it is parsed, and again by the server).
   *  `roleOfferRaw` is the parameter as it arrived, so a ceremony that is resumed carries the same bytes. */
  roleOffer?: RoleOfferV1;
  roleOfferRaw?: string;
  /** workspace-member-invite: where the invited person picks the invitation up IN THE APP — the page the
   *  message the host's agent sends them points at. Accepted only on the relying app's own origin. */
  appLink?: string;
  existingOrg?: Address; // org_create: reuse an EXISTING org the person stewards — grant from it instead of deploying a new one
  sessionKey?: Address; // spec 270 v4 W2 — the relying app's session-key address; the home signs the DEL-001 leaf for it
  payAmount?: string; // spec 272 — x402 charge amount (atomic units) the relying app requested (tier price); capped by the client's paymentConfig
  subPeriod?: number; // spec 272 recurring — when set, this is a SUBSCRIPTION: the billing-period length (seconds). The home also mints a standing pull mandate.
  collectToken?: string; // spec 272 recurring — owner id_token passed by the owner app for the `subscription-collect` ceremony (authorizes the a2a due/collected calls).
  contentSignerTarget?: string; // spec 266 — the single signing identity (e.g. demo-validator.impact) this `content-signer` ceremony authorizes. Per-custodian: you authorize only the SA you connected as.
  prompt?: string; // OIDC `prompt`: 'select_account'/'login' force the custodian chooser instead of silently reusing the active session (multi-custodian admin must never assume an identity).
  requireNamedAgent?: boolean; // relying app requires a unique Impact name before issuing the grant.
  /** org-create + a registry: the org's registration (presence, affirmed clauses, contact) as the app sent it,
   *  base64url JSON, parsed and checked by `mission-registry.ts` — see `RelyingApp.missionRegistryConfig`. */
  registryEntry?: string;
  /** org-create (Global.Church, 2026-10-21): the organization's TYPE as the app asked for it (`org_type`, base64url
   *  JSON, checked by `lib/org-type.ts`). Stored with a NEW organization in its `org.profile`. */
  orgType?: OrgTypeV1;
  /** org-create (2026-10-22): the new organization's display name as the app's person typed it (`org_name`). Stored
   *  as its `org.profile` displayName; the handle (`org_base`) stays its name on chain. */
  orgDisplayName?: string;
  /** Spec 397 — the HOST connecting through a Home MCP (Claude, Muse, …), as the Worker's registration names it. A
   *  display hint for the consent and the Connected card only; the template and delegate come from the registry. */
  viaHost?: string;
}

// SEC-005: ALLOWED_RELYING_ORIGINS is now derived from whitelabel.relyingApps[].redirect_uris
// via `isAllowedRelyingOrigin` (imported above). The previously-hardcoded array is removed
// to prevent drift between the OIDC client registry and the cross-origin postMessage gate.

export function parseEnrollReq(): EnrollReq | null {
  try {
    const p = new URL(window.location.href).searchParams;
    const clientId = p.get('client_id');
    const redirectUri = p.get('redirect_uri');
    const agentName = p.get('agent_name');
    // `delegate` in the URL is an UNTRUSTED HINT anyway (SEC-001 — /oidc/authorize-grant returns the
    // registry-derived delegate, which overrides this). So a registered client may OMIT it and get the
    // registry value here too (openbook-tyndale sends a plain OIDC request with no delegate — without
    // this default the request wasn't recognized as an enroll at all and the member was never
    // redirected back). Unregistered client + no delegate still returns null.
    const delegate = p.get('delegate') ?? (clientId ? (knownRelyingClient(clientId)?.delegate ?? null) : null);
    const codeChallenge = p.get('code_challenge');
    // `delegation_template` is ours; accept `template` as an alias for plain-OIDC relying apps.
    const template = p.get('delegation_template') ?? p.get('template');
    // spec 257 §11: `agent_name` is OPTIONAL — when absent the OP runs the credential ceremony and
    // (Google) deploys a NAMELESS SA; `sub`/`canonical_agent_id` is the sole load-bearing identity.
    // The other fields stay MANDATORY (client_id, redirect_uri, delegate, code_challenge, template) —
    // with delegate/template satisfiable from the registry/alias as above.
    if (!clientId || !redirectUri || !delegate || !codeChallenge || !template) return null;
    const responseType = p.get('response_type');
    if (responseType && responseType !== 'code') return null; // code flow only (spec 230 §4.1)
    const ccm = p.get('code_challenge_method');
    if (ccm && ccm !== 'S256') return null; // S256 PKCE only
    return {
      aud: clientId,
      redirectUri,
      state: p.get('state') ?? '',
      name: agentName ?? '',
      delegate: delegate as Address,
      nonce: p.get('nonce') ?? '',
      codeChallenge,
      template,
      orgBase: p.get('org_base') ?? undefined,
      purpose: p.get('org_purpose') ?? undefined,
      grantOrg: (p.get('grant_org') as Address) ?? undefined,
      member: (p.get('member') as Address) ?? undefined,
      ...roleOfferFromParam(p.get('role_offer')),
      appLink: sameOriginLink(p.get('app_link'), redirectUri),
      existingOrg: (p.get('existing_org') as Address) ?? undefined,
      sessionKey: (p.get('session_key') as Address) ?? undefined,
      payAmount: /^\d+$/.test(p.get('pay_amount') ?? '') ? (p.get('pay_amount') as string) : undefined,
      subPeriod: /^\d+$/.test(p.get('sub_period') ?? '') ? Number(p.get('sub_period')) : undefined,
      collectToken: p.get('collect_token') ?? undefined,
      contentSignerTarget: p.get('content_signer_target') ?? undefined,
      prompt: p.get('prompt') ?? undefined,
      requireNamedAgent: p.get('require_named_agent') === 'true' || p.get('require_named_agent') === '1',
      registryEntry: p.get('registry_entry') ?? undefined,
      orgType: parseOrgTypeParam(p.get('org_type')) ?? undefined,
      orgDisplayName: checkOrgDisplayName(p.get('org_name')) ?? undefined,
      viaHost: (p.get('via_host') ?? '').replace(/[^\p{L}\p{N} .,'()&_-]/gu, '').trim().slice(0, 60) || undefined,
    };
  } catch {
    return null;
  }
}

/** A link a relying app may put in front of a person: https, and on the app's own registered origin. */
function sameOriginLink(link: string | null, redirectUri: string): string | undefined {
  if (!link) return undefined;
  try {
    const u = new URL(link);
    if (u.protocol !== 'https:' || u.origin !== new URL(redirectUri).origin) return undefined;
    return u.toString().slice(0, 500);
  } catch {
    return undefined;
  }
}

export function hostOf(redirectUri: string): string {
  try {
    return new URL(redirectUri).host;
  } catch {
    return redirectUri;
  }
}

export function relyingAllowed(redirectUri: string): boolean {
  return relyingOriginAllowed(redirectUri);
}

// ── Standalone grant + delivery (used by the hook AND the Google-resume path) ──────────────
// The Google enrollment path redirects out to the broker, so on return the enroll request is
// no longer in the URL — it's restored from a sessionStorage stash. These module-level helpers
// let that resumed flow finish the ceremony with the SAME wire behavior as the in-page hook.

/** Post to the opener ONLY at the validated relying origin (audit F3 — exact targetOrigin). */
export function postEnrollToOpener(enroll: EnrollReq, msg: Record<string, unknown>): void {
  if (typeof window === 'undefined' || !window.opener || !relyingAllowed(enroll.redirectUri)) return;
  try {
    window.opener.postMessage(msg, new URL(enroll.redirectUri).origin);
  } catch {
    /* ignore */
  }
}

/** Server-minted enrollment-grant ticket (SEC-001). The SPA calls this BEFORE running
 *  the ROOT-credential ceremony so the server has bound `{client_id, redirect_uri,
 *  agent_name, delegate (from REGISTRY), code_challenge, nonce, template}` under a
 *  grant_id. The grant_id + the registry-derived `delegate` come back; the SPA uses
 *  the latter (NOT the URL-supplied `delegate`) when constructing the delegation. */
export async function beginEnrollmentGrant(
  enroll: EnrollReq,
  resolvedName: string,
  /** The home's address: the email verified in this window is keyed by it (lib/verified-email). */
  homeAddress?: string,
): Promise<{ grant_id: string; delegate: Address }> {
  // The member's HUMAN name, for a client the REGISTRY scopes for `profile`. This is the one place
  // every grant path passes through — the journey, the recognized fast path, the social resume and
  // org-create all call it — so reading it here is what makes "the app gets a name" true for every
  // credential family instead of whichever one someone remembered to wire.
  //
  // Costs nothing for an unscoped client: `sharesProfileName` is false, and no read happens at all.
  //
  // The email rides the same read for a client the registry names it for (R5.3) — one vault round
  // trip answers both, and each field is gated on its own registered permission.
  const relying = knownRelyingClient(enroll.aud);
  const wantsName = sharesProfileName(relying);
  const wantsEmail = sharesEmailClaim(relying);
  const profile = wantsName || wantsEmail ? await profileForConnect() : { name: '', email: '' };
  const profileName = wantsName ? profile.name : '';
  // The vault profile is seeded AFTER a first sign-in, in the background (EmailAuthCard); a host who presses
  // Allow within a few seconds found it empty and got a token with no email — on the one sign-in Gather27's
  // listing form needs it. The email verified by code a moment ago is the same address (2026-10-15).
  const profileEmail = wantsEmail ? profile.email || (homeAddress ? verifiedEmailFor(homeAddress) : '') : '';
  const r = await fetch('/oidc/authorize-grant', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      client_id: enroll.aud,
      redirect_uri: enroll.redirectUri,
      nonce: enroll.nonce,
      code_challenge: enroll.codeChallenge,
      code_challenge_method: 'S256',
      agent_name: resolvedName,
      ...(profileName ? { profile_name: profileName } : {}),
      ...(profileEmail ? { profile_email: profileEmail } : {}),
      delegation_template: enroll.template,
    }),
  });
  const b = (await r.json().catch(() => ({}))) as { grant_id?: string; delegate?: Address; error?: string };
  if (!r.ok || !b.grant_id || !b.delegate) {
    throw new Error(b.error ?? `authorize-grant failed (HTTP ${r.status})`);
  }
  return { grant_id: b.grant_id, delegate: b.delegate };
}

/** Redeem the grant by presenting the signed delegation. The grant is single-use.
 *  /oidc/grant verifies the delegation's `delegate` matches what was bound at
 *  /authorize-grant time + verifies ERC-1271 + records `oidc-deleg:<digest> → client_id`
 *  so silent re-auth can't replay the delegation against a different client (SEC-002). */
export async function submitEnrollGrant(
  grantId: string,
  delegationWire: unknown,
  org?: unknown,
  sessionDelegation?: unknown,
  paymentDelegation?: unknown,
  settlementHash?: string,
  treasury?: string | null,
  pullDelegation?: unknown,
  /** spec 345 — the self-vault grant riding this same plain sign-in, when the client declares one. */
  selfVaultGrant?: unknown,
  /** spec 397 §11 — the act-as-me standing wires (one per capability), beside the ask wire. */
  delegations?: unknown[],
): Promise<string> {
  const r = await fetch('/oidc/grant', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ grant_id: grantId, delegation: delegationWire, org, sessionDelegation, paymentDelegation, settlementHash, treasury, pullDelegation, selfVaultGrant, ...(delegations ? { delegations } : {}) }),
  });
  const b = (await r.json().catch(() => ({}))) as { code?: string; error?: string };
  if (!r.ok || !b.code) throw new Error(b.error ?? `grant failed (HTTP ${r.status})`);
  return b.code;
}

/** Deliver the code back: popup → postMessage (exact origin) + close; else full-page ?code&state.
 *  Falls back to a redirect if the popup lost its opener (cross-origin OAuth round-trip). */
export function deliverEnrollCode(enroll: EnrollReq, popupMode: boolean, code: string): void {
  // THE APP'S DEFAULTS, BEFORE THE CODE GOES BACK (`src/lib/client-defaults.ts`): a person connecting from the
  // card room leaves with the card room's skills on their agent and its default coach hired — the first hand
  // has a coach, and nobody is asked to go and set it up. Bounded (a minute) and never fatal: a failure is
  // logged, the code is delivered anyway, and the app's own sheet offers the Coaches page.
  // ON THE SIGN-IN ONLY. Every ceremony delivers a code — a workspace join, an invitation, a charter, a
  // wire — and each one spent fifteen seconds re-checking the card room's defaults (already applied, all
  // skipped) before the person was sent back: a join that took thirty seconds was half this. The defaults
  // are about ARRIVING, and arriving is the plain sign-in.
  const plainSignIn = !enroll.template || enroll.template === 'site-login' || isPaymentTemplate(enroll.template);
  if (code && plainSignIn && CLIENT_DEFAULTS[enroll.aud]) {
    // FORCED, AND SAID. The defaults are tried, tried once more if they failed (a vault that was a second
    // late, a signer that had not warmed), and whatever is still missing goes BACK WITH THE CODE as
    // `defaults_error`, so the app can tell the person what did not happen and where to finish it —
    // a person who arrived by email sat down with the house coach and no word about why (2026-09-13).
    const deadline = new Promise<{ error?: string }>((resolve) => setTimeout(() => resolve({ error: 'timed out after a minute' }), 90_000));
    const attempt = () => applyClientDefaults(enroll.aud, (line) => console.log('[client-defaults]', line)).catch((e: unknown) => ({ applied: [], skipped: [], error: e instanceof Error ? e.message : String(e) }));
    void Promise.race([
      attempt().then(async (o) => {
        if (!o.error) return o;
        console.warn('[client-defaults]', enroll.aud, 'first try:', o.error);
        return attempt();
      }),
      deadline,
    ]).then((o) => {
      if (o.error) console.warn('[client-defaults]', enroll.aud, o.error); else console.log('[client-defaults]', enroll.aud, 'applied', (o as { applied?: string[] }).applied, 'skipped', (o as { skipped?: string[] }).skipped);
      deliverEnrollCodeNow(enroll, popupMode, code, o.error);
    });
    return;
  }
  deliverEnrollCodeNow(enroll, popupMode, code);
}

function deliverEnrollCodeNow(enroll: EnrollReq, popupMode: boolean, code: string, defaultsError?: string): void {
  if (popupMode && typeof window !== 'undefined' && window.opener && relyingAllowed(enroll.redirectUri)) {
    postEnrollToOpener(enroll, { type: 'AC_SUCCESS', state: enroll.state, code });
    window.close();
    return;
  }
  const url = new URL(enroll.redirectUri);
  url.searchParams.set('code', code);
  url.searchParams.set('state', enroll.state);
  // Carry the MINTING origin (this Home — possibly a `<label>` subdomain we hopped to from a nameless apex
  // enroll) so the relying app exchanges the code + verifies the id_token `iss` HERE, not at the apex it
  // opened. Without this, a hopped popup/redirect breaks the exchange (iss mismatch — wallet/passkey only;
  // social FedCMs server-side and never hops). Read by the relying app's `relayCodeIfPopupReturn` / `?code`
  // return handler (spec 295); harmless to apps that ignore it. (The postMessage path above needs no marker
  // — the opener reads the message's `e.origin`, which IS this minting origin.)
  if (typeof window !== 'undefined') url.searchParams.set('ac_iss', window.location.origin);
  if (defaultsError) url.searchParams.set('defaults_error', defaultsError.slice(0, 300));
  // spec 257: if we ARE a popup but lost our opener (the OAuth IdP — e.g. Google COOP — severs
  // window.opener on the cross-origin round-trip), we can't postMessage the code back. Redirect
  // THIS popup to the relying app with a relay marker so it hands {code,state} to its same-origin
  // opener window (which holds the PKCE verifier) and closes, instead of trying to finish the
  // exchange itself. Marker is only set for popupMode, so the plain full-page redirect (popup
  // blocked / mobile, greenfield 11) is unchanged, and apps that don't handle it just ignore it.
  if (popupMode) url.searchParams.set('ac_relay', '1');
  leaveForApp(url);
}

/** Hand the person back to the relying app by REPLACING this page in the browser's history, never by adding
 *  to it. With a plain navigation, Back from the app landed on this window again — restored from the
 *  back/forward cache exactly as it was left, "Returning you to <app>…" over a bar that never finishes,
 *  because the script that would move it on has already run (Global.Church, 2026-10-12). Replaced, Back
 *  from the app goes to wherever the person was before they started signing in. */
function leaveForApp(url: URL): void {
  window.location.replace(url.toString());
}

/** spec 272 recurring — deliver a subscription-collection RESULT back to the owner app (no OIDC code).
 *  Popup → postMessage {collected, attempted} + close; else full-page redirect with the result in query. */
export function deliverCollectResult(enroll: EnrollReq, popupMode: boolean, result: { collected: number; attempted: number }, kind?: string): void {
  if (popupMode && typeof window !== 'undefined' && window.opener && relyingAllowed(enroll.redirectUri)) {
    postEnrollToOpener(enroll, { type: 'AC_COLLECT', state: enroll.state, kind, ...result });
    window.close();
    return;
  }
  const url = new URL(enroll.redirectUri);
  url.searchParams.set('collect', '1');
  url.searchParams.set('collected', String(result.collected));
  url.searchParams.set('attempted', String(result.attempted));
  if (kind) url.searchParams.set('collect_kind', kind);
  url.searchParams.set('state', enroll.state);
  leaveForApp(url);
}

/** OIDC error bounce (spec 230 §4.3 / prompt=none silent SSO): deliver `?error&state` back to the
 *  relying app with NO UI. Popup → postMessage (exact origin) + close; else full-page redirect.
 *  Standard values a relying app's connect client handles: `login_required` (no home session — the
 *  app clears its silent-SSO hint) / `interaction_required` (a session exists but a silent grant
 *  would mint delegations without a consent gesture) / `access_denied`. */
export function deliverEnrollError(enroll: EnrollReq, popupMode: boolean, error: string): void {
  if (popupMode && typeof window !== 'undefined' && window.opener && relyingAllowed(enroll.redirectUri)) {
    postEnrollToOpener(enroll, { type: 'AC_ERROR', state: enroll.state, error });
    window.close();
    return;
  }
  const url = new URL(enroll.redirectUri);
  url.searchParams.set('error', error);
  url.searchParams.set('state', enroll.state);
  leaveForApp(url);
}

export interface EnrollApi {
  enroll: EnrollReq | null;
  popupMode: boolean;
  allowed: boolean;
  /** True while a MEMBER-REGISTERED client is being looked up. `allowed` is not yet meaningful —
   *  wait, rather than rendering "request blocked" at an app that is in fact registered. */
  resolvingClient: boolean;
  host: string;
  postToOpener(msg: Record<string, unknown>): void;
  /** OIDC error bounce to the relying app (prompt=none outcomes) — see deliverEnrollError. */
  deliverError(error: string): void;
  /** Server-mint the enrollment grant (SEC-001). Returns the grant_id + the canonical
   *  delegate the SPA MUST use when building the delegation (which overrides the
   *  URL-supplied `enroll.delegate` — anti-spoof). Call this BEFORE the ceremony. */
  beginGrant(resolvedName: string): Promise<{ grant_id: string; delegate: Address }>;
  /** Redeem a server-minted grant by presenting the signed delegation. `sessionDelegation` (spec 270 v4
   *  W2) is the DEL-001 leaf the home signed for the relying app's session key — carried to /token. */
  submitGrant(grantId: string, delegationWire: unknown, org?: unknown, sessionDelegation?: unknown, paymentDelegation?: unknown, settlementHash?: string, treasury?: string | null, pullDelegation?: unknown, selfVaultGrant?: unknown): Promise<string>;
  deliverCode(code: string): void;
  denyEnroll(): void;
}

export function useEnrollReq(): EnrollApi {
  const [enroll] = useState<EnrollReq | null>(() => (typeof window === 'undefined' ? null : parseEnrollReq()));
  const [popupMode] = useState<boolean>(() => {
    if (typeof window === 'undefined') return false;
    // Do NOT require `window.opener`: this Connect origin sets COOP (same-origin-allow-popups), which
    // severs the cross-origin opener as soon as the popup loads us — so `window.opener` is null inside
    // the popup even though we ARE the popup ceremony. `mode=popup` is the reliable signal. Delivery
    // still falls back to the same-origin relay (`ac_relay`) when postMessage can't reach the opener.
    return !!enroll && new URL(window.location.href).searchParams.get('mode') === 'popup';
  });

  // Stash as soon as authorize is parsed — not only when they click Google. A new home that
  // lands on `/` after email/Google must still find this request and finish consent.
  useEffect(() => {
    if (!enroll) return;
    writePendingEnroll({ enroll, popupMode, name: enroll.name ?? '' });
  }, [enroll, popupMode]);

  // RESOLVE BEFORE DECIDING. A member-registered client is not in this bundle, so `allowed`
  // cannot be answered until `/connect/client-info` has replied. `resolvingClient` is true for
  // that window, and the entry screen waits rather than flashing "request blocked" at an app
  // that is perfectly well registered — a false accusation the person cannot act on.
  //
  // A curated client resolves synchronously, so this never delays the common path.
  const [resolvingClient, setResolvingClient] = useState<boolean>(
    () => !!enroll && !knownRelyingClient(enroll.aud),
  );
  const [, setResolvedTick] = useState(0);
  useEffect(() => {
    if (!enroll || knownRelyingClient(enroll.aud)) {
      setResolvingClient(false);
      return;
    }
    let live = true;
    void primeRelyingClient(enroll.aud).finally(() => {
      if (!live) return;
      setResolvingClient(false);
      setResolvedTick((n) => n + 1); // re-read the now-populated origin allowlist
    });
    return () => {
      live = false;
    };
  }, [enroll]);

  // Post to the opener ONLY at the validated relying origin (audit F3 — exact targetOrigin).
  const postToOpener = useCallback(
    (msg: Record<string, unknown>) => {
      if (enroll) postEnrollToOpener(enroll, msg);
    },
    [enroll],
  );

  // Server-mint the enrollment grant (SEC-001 — split from submitGrant so the
  // ceremony runs against the registry-derived delegate, not the URL-supplied one).
  const beginGrant = useCallback(
    async (resolvedName: string): Promise<{ grant_id: string; delegate: Address }> => {
      if (!enroll) throw new Error('no request');
      return beginEnrollmentGrant(enroll, resolvedName);
    },
    [enroll],
  );

  // Redeem the grant by presenting the signed delegation.
  const submitGrant = useCallback(
    async (grantId: string, delegationWire: unknown, org?: unknown, sessionDelegation?: unknown, paymentDelegation?: unknown, settlementHash?: string, treasury?: string | null, pullDelegation?: unknown, selfVaultGrant?: unknown): Promise<string> => {
      return submitEnrollGrant(grantId, delegationWire, org, sessionDelegation, paymentDelegation, settlementHash, treasury, pullDelegation, selfVaultGrant);
    },
    [],
  );

  // Deliver the code back (popup postMessage exact origin; or full-page ?code&state). The
  // token never travels in the URL — only the code.
  const deliverCode = useCallback(
    (code: string) => {
      if (enroll) deliverEnrollCode(enroll, popupMode, code);
    },
    [enroll, popupMode],
  );

  const denyEnroll = useCallback(() => {
    if (!enroll) return;
    if (popupMode) {
      postToOpener({ type: 'AC_CANCEL', state: enroll.state });
      window.close();
      return;
    }
    const url = new URL(enroll.redirectUri);
    url.searchParams.set('enroll_error', 'denied');
    url.searchParams.set('state', enroll.state);
    leaveForApp(url);
  }, [enroll, popupMode, postToOpener]);

  const deliverError = useCallback(
    (error: string) => {
      if (enroll) deliverEnrollError(enroll, popupMode, error);
    },
    [enroll, popupMode],
  );

  return {
    enroll,
    popupMode,
    allowed: enroll ? relyingAllowed(enroll.redirectUri) : false,
    resolvingClient,
    host: enroll ? hostOf(enroll.redirectUri) : '',
    postToOpener,
    deliverError,
    beginGrant,
    submitGrant,
    deliverCode,
    denyEnroll,
  };
}

/**
 * CEREMONY templates — the owner-operations that run ON the home session instead of minting a grant
 * for a relying app (content-signer, subscription-collect, service-agent-wire).
 *
 * ONE predicate, because this used to be six hand-written `t === 'a' || t === 'b'` lists spread
 * across EntryExperience, RecognizedEnroll and GoogleEnrollResume, and adding a template meant
 * finding all six. Missing one does not fail loudly: the request quietly completes down the ordinary
 * site-login pipeline — one signature, a bare `?code`, nothing stored — which looks like success from
 * the outside. service-agent-wire was added to three of the six and lost twice to the other three.
 */
export const CEREMONY_TEMPLATES = ['content-signer', 'subscription-collect', 'service-agent-wire'] as const;

/**
 * Templates that DEPLOY A NEW AGENT rather than minting a site-login grant.
 *
 * `person-create` — ANOTHER PERSON OF THE CONNECTED CUSTODIAN'S OWN. A relying app asks for it when
 * somebody takes on a name inside it: a character in a game, a handle in a community. The agent is
 * person-class, `.me`-named, custodied by the same credential, and NEVER the default — their own name stays
 * the one their Home opens as. It is idempotent by LABEL: asking twice for the same name is asking about the
 * same person, which is what lets the same character come back for the next game with everything it learned.
 */
export function isDeployTemplate(template: string | undefined | null): boolean {
  return template === 'org-create' || template === 'workspace-create' || template === 'person-create';
}

export function isCeremonyTemplate(template: string | undefined | null): boolean {
  return !!template && (CEREMONY_TEMPLATES as readonly string[]).includes(template);
}
