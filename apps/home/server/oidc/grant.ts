// POST /oidc/grant — redeem a server-minted enrollment grant for an OIDC authorization
// code (spec 230 §4.2; SEC-001 + SEC-002 closure).
//
// The home SPA at /authorize first POSTs to /oidc/authorize-grant to obtain a `grant_id`
// bound to the validated client registry + the registered delegate. The SPA then runs
// the ROOT-credential ceremony to sign a delegation whose `delegate` equals that
// registered delegate. It POSTs HERE with { grant_id, delegation, org? }. We:
//
//   1. enforce same-origin (Origin === iss): non-SPA callers are rejected.
//   2. look up the bound grant by `grant_id` and DELETE it (single-use).
//   3. verify the supplied delegation — ERC-1271 against the delegator, the timestamp
//      window — and reject if its delegate, agent-name resolution, or template don't
//      match the stored grant.
//   4. mint the id_token + a single-use authorization code bound to the grant's PKCE
//      challenge + client_id + redirect_uri, AND record `oidc-deleg:<digest> → client_id`
//      so the silent-reauth path at /token cannot mint id_tokens for the wrong client
//      (SEC-002).
//
// The OIDC code (not the token) is what travels back in the redirect/popup; /token does
// the PKCE exchange.

import { mintIdToken, newAuthCode } from '@agenticprimitives/connect';
import { checkOrgDisplayName, checkOrgType } from '../../src/lib/org-type';
import { toCanonicalAgentId } from '@agenticprimitives/identity-directory-adapters';
import { getServer, json, resolveOrigin, type FnContext } from '../_lib/server-broker';
import { verifyDelegation, type IncomingDelegation } from '../_lib/verify-delegation';
import { CHAIN_ID } from '../../src/lib/chain';
import { getClient } from '../../src/lib/oidc-clients';
import type { StoredEnrollmentGrant } from './authorize-grant';
import { idTokenTtl } from '../_lib/session-ttl';
import { nameClaimForIdToken } from '../../src/lib/new-member';
import { defaultOrgContact } from '../_lib/contact-directory';
import { operatorOrg, recordOrgDefault } from '../_lib/operator-directory';

const CODE_TTL_MS = 300_000; // 5 min PKCE exchange window

interface GrantBody {
  grant_id?: string;
  delegation?: IncomingDelegation;
  org?: unknown;
  /** spec 270 v4 W2 — the DEL-001 leaf the home signed for the relying app's session key. */
  sessionDelegation?: unknown;
  /** spec 272/243 — the x402 `person-treasury → payee` payment delegation the member authorized at
   *  connect (template `x402-pay`). Its `delegate` is the OPEN sentinel (push) or the payee treasury
   *  (pull), NOT `client.delegate`, so it is NOT subject to the site-delegate match — only ERC-1271 +
   *  window. Carried alongside `delegation` (like `sessionDelegation`); the relying app stores it in
   *  the payee's vault and redeems it per paid read. The PaymentEnforcer caps every charge on-chain. */
  paymentDelegation?: IncomingDelegation;
  /** spec 272 — the settlement tx hash of the FIRST charge done IN the ceremony (all-custodian, via
   *  chargePayment). Opaque to the home; carried to the relying app, which verifies it on-chain + mints
   *  the access pass. */
  settlementHash?: string;
  /** spec 272 recurring — the standing `treasury → payee` PULL mandate minted for a SUBSCRIPTION connect
   *  (delegate = payee). Carried to the relying app, which stores it in the payee's vault for renewal. Like
   *  `paymentDelegation`, it is ERC-1271-verified, NOT client.delegate-matched (its delegate is the payee). */
  pullDelegation?: IncomingDelegation;
  /** The member's person-treasury SA address (or null if they have none yet). Resolved at connect from
   *  the home's managed-agent tree and carried to the relying app so it can gate ALL financial ops up
   *  front — a member with no treasury is told to create one rather than shown a no-op Buy-access flow. */
  treasury?: string | null;
  /** spec 345 — the self-vault grant (delegator = delegate = the person), when the client's
   *  whitelabel entry declared `self_vault_grant`. Independently ERC-1271-verified below, reusing
   *  the SAME delegator already proven for the main site delegation. */
  selfVaultGrant?: IncomingDelegation;
  /** Spec 397 §11 — `act-as-me`: the STANDING WIRES of the set, one per capability, each to the client's ACT key
   *  (`grant.delegate`); the main `delegation` is then the ask wire to the client's `ask_delegate`. Each wire is
   *  verified on its own (ERC-1271 + window against ITS delegator — the person, or her treasury for a payment). */
  delegations?: Array<{ v: 1; template: string; capability: string; wire: IncomingDelegation; ref: string; requirement: Record<string, unknown> }>;
}

export const onRequestPost = async ({ request, env }: FnContext): Promise<Response> => {
  // One lifetime for this request: the minted token, and any KV binding that must not outlive it.
  const ttl = idTokenTtl(env);
  // SEC-001 (origin check): /oidc/grant is reachable ONLY from the home SPA. A
  // non-browser caller, or a cross-origin browser caller, is rejected here.
  const iss = resolveOrigin(request, env);
  const reqOrigin = request.headers.get('origin');
  if (!reqOrigin || reqOrigin !== iss) {
    return json({ error: 'grant must be called from the home origin' }, 403);
  }

  const body = (await request.json().catch(() => null)) as GrantBody | null;
  if (!body?.grant_id || !body.delegation) {
    return json({ error: 'grant_id + delegation required' }, 400);
  }

  // Look up the server-bound grant (single-use: delete-after-read).
  const grantKey = `oidc-grant:${body.grant_id}`;
  const raw = await env.AUTH_CODES.get(grantKey);
  await env.AUTH_CODES.delete(grantKey);
  if (!raw) return json({ error: 'invalid or already-used grant_id' }, 400);
  const grant = JSON.parse(raw) as StoredEnrollmentGrant;

  // Delegate binding: the supplied delegation's `delegate` MUST equal the delegate
  // recorded at /authorize-grant time (which came from the OIDC client registry, NOT
  // from the request). This closes the "attacker chooses delegate" attack.
  // Spec 397 §11 — under `act-as-me` the main delegation is the ASK wire, bound to the client's ask key; the act
  // wires (`delegations[]`) are each bound to the registered ACT key (`grant.delegate`). Any other template: as before.
  const actTemplate = grant.delegation_template === 'act-as-me';
  const actClient = actTemplate ? getClient(grant.client_id) : null;
  const expectedMain = actTemplate ? (actClient?.ask_delegate ?? '') : grant.delegate;
  if (!expectedMain || body.delegation.delegate.toLowerCase() !== expectedMain.toLowerCase()) {
    return json({ error: 'delegation delegate does not match the registered client delegate' }, 401);
  }
  if (actTemplate) {
    if (!Array.isArray(body.delegations) || body.delegations.length === 0) return json({ error: 'act-as-me needs at least one act wire' }, 400);
    const caps = new Set<string>();
    for (const w of body.delegations) {
      if (!w || w.v !== 1 || w.template !== 'act-as-me' || typeof w.capability !== 'string' || !w.wire || typeof w.ref !== 'string' || !w.requirement) return json({ error: 'an act wire is malformed' }, 400);
      if (caps.has(w.capability)) return json({ error: `two act wires for ${w.capability} — one wire per capability` }, 400);
      caps.add(w.capability);
      if (String(w.wire.delegate).toLowerCase() !== grant.delegate.toLowerCase()) return json({ error: `the act wire for ${w.capability} does not name the registered act key` }, 401);
      const isPayment = w.capability === 'treasury.payment.execute';
      if (!isPayment && String(w.wire.delegator).toLowerCase() !== body.delegation.delegator.toLowerCase()) return json({ error: `the act wire for ${w.capability} is not the connecting person's` }, 401);
      const wv = await verifyDelegation(env, w.wire);
      if (!wv.ok) return json({ error: `act wire for ${w.capability} failed: ${wv.reason}` }, 401);
      if (wv.digest.toLowerCase() !== w.ref.toLowerCase()) return json({ error: `the act wire for ${w.capability} does not hash to its ref` }, 401);
    }
  }

  // ERC-1271 + timestamp-window verification. On success returns the canonical EIP-712
  // digest, which we use as the silent-reauth binding key.
  //
  // ALL of them AT ONCE. These are independent proofs — different delegators, different digests,
  // none derived from another — and each one carries its own bounded retry ladder against
  // read-replica lag (verify-delegation.ts), because `approveGrantHashes` landed a userOp seconds
  // ago. Run one after another, a plain sign-in carrying a self-vault grant pays two of those
  // ladders end to end; run together it pays one. The checks below keep their original order, so a
  // request with more than one bad proof still fails with the same message it always did.
  const [v, payV, pullV, selfV] = await Promise.all([
    verifyDelegation(env, body.delegation),
    // spec 272/243 — an x402 payment delegation, verified independently (ERC-1271 + window against
    // ITS delegator = the person's treasury SA). NOT delegate-matched to the client (its delegate is
    // the OPEN sentinel / the payee treasury). Reject an invalid one rather than silently dropping it.
    body.paymentDelegation ? verifyDelegation(env, body.paymentDelegation) : null,
    // spec 272 recurring — same independent verification for the standing subscription PULL mandate.
    body.pullDelegation ? verifyDelegation(env, body.pullDelegation) : null,
    // spec 345 — the self-vault grant is delegator = delegate = the SAME person; verified on its own
    // rather than trusted because the site delegation checked out. NOT delegate-matched to the client
    // (its delegate is the person, not client.delegate).
    body.selfVaultGrant ? verifyDelegation(env, body.selfVaultGrant) : null,
  ]);
  if (!v.ok) return json({ error: `delegation proof failed: ${v.reason}` }, 401);
  if (payV && !payV.ok) return json({ error: `payment delegation proof failed: ${payV.reason}` }, 401);
  if (pullV && !pullV.ok) return json({ error: `pull delegation proof failed: ${pullV.reason}` }, 401);
  if (body.selfVaultGrant) {
    if (body.selfVaultGrant.delegator.toLowerCase() !== body.delegation.delegator.toLowerCase()) {
      return json({ error: 'self-vault grant delegator does not match the connecting person' }, 401);
    }
    if (selfV && !selfV.ok) return json({ error: `self-vault grant proof failed: ${selfV.reason}` }, 401);
  }

  // Mint the id_token bound to the grant's client + nonce + agent_name.
  //
  // NAME ON THE TOKEN, for an account that has no handle. `agent_name` is the `<label>.me` name
  // from the naming service, and `mintIdToken` omits the claim entirely when it is empty — which is
  // exactly what a nameless account produces, and why players show up as `0x1a2b…9f0e`. Accounts
  // created through first-connect setup are nameless ON PURPOSE (a handle is globally unique and
  // claiming one for everybody who signs up is the wrong trade), so the name they DO have is the
  // human one on their private profile, carried here by the home SPA at /oidc/authorize-grant and
  // already gated there on the client's registered `profile` scope.
  //
  // It fills in ONLY when there is no handle. A member with a real `<label>.me` name keeps it on
  // the claim, so nothing an app resolves today changes meaning; the substitution can only turn an
  // ABSENT claim into a present one. The distinct `profile_name` on the /token response below says
  // which of the two an app received, for anything that needs to tell them apart.
  const sub = toCanonicalAgentId(CHAIN_ID, body.delegation.delegator);
  const { signer } = await getServer(env);
  const profileName = (grant.profile_name ?? '').trim();
  // Already gated at /oidc/authorize-grant against the client's registered `idTokenClaims`, so an
  // unpermitted client's grant carries '' here and the claim is simply absent from the payload.
  const profileEmail = (grant.profile_email ?? '').trim();
  const idToken = await mintIdToken(
    {
      iss,
      sub,
      aud: grant.client_id,
      nonce: grant.nonce || undefined,
      agentName: nameClaimForIdToken(grant.agent_name, profileName),
      ...(profileEmail ? { email: profileEmail } : {}),
      // The standard `name` claim: the HUMAN name for a profile-scoped client, beside `agent_name` (the handle when
      // there is one) — so an app that greets a person by name does not have to tell a handle from a name.
      ...(profileName ? { name: profileName } : {}),
      ttlSeconds: ttl,
    },
    signer,
  );

  // SEC-002 closure: bind the canonical delegation digest to its originating client.
  // /token grant_type=delegation re-verifies that any silent-reauth request with this
  // delegation matches this client_id, so a leaked delegation can't be replayed to
  // mint id_tokens for a DIFFERENT relying app.
  await env.AUTH_CODES.put(
    `oidc-deleg:${v.digest.toLowerCase()}`,
    // The profile name rides the binding too: /token's SILENT RE-AUTH mints from this record, not
    // from a grant, so without it a nameless member would have a name on their first token and none
    // on every one after — the seat label would vanish the moment the app refreshed its session.
    // The email rides it for exactly the same reason as the name: a silent re-auth mints from this
    // record, so leaving it off would put the claim on the first token and on none of the ones after.
    JSON.stringify({ client_id: grant.client_id, agent_name: grant.agent_name, profile_name: profileName, profile_email: profileEmail }),
    { expirationTtl: ttl },
  );

  // ADR-0025 / spec 246: persist the private related-agent link into the person's
  // vault (Connect-home KV) during this authenticated, home-origin-only ceremony.
  // `requestedBy` is the SERVER-authoritative client_id (not from the request body).
  // The relying app later reads it back via /connect/related-orgs (person-session-auth).
  const orgPayload = body.org as {
    orgAgent?: string; orgName?: string; person?: string; purpose?: string;
    kind?: string; parent?: string;
    /** workspace-create since 2026-10-02: the ORGANIZATION that governs this workspace (`aporg:governedBy`), with
     *  its name. `orgAgent` stays the workspace — every field an app reads is unchanged — and this names what it
     *  hangs under and where its membership lives. Returned verbatim on `/token` with the rest of `org`. */
    governor?: string; governorName?: string;
    proofHash?: string; credential?: unknown; brokerDelegation?: { delegate?: string } | null;
    membershipDelegation?: unknown; stewardshipDelegation?: unknown; operationalDelegation?: unknown;
    readGrantDelegation?: unknown;
    /** Global.Church 2026-10-21: the type chosen for a NEW organization (lib/org-type.ts). Re-checked here. */
    orgType?: unknown;
    /** 2026-10-22: a NEW organization's display name (lib/org-type.ts checkOrgDisplayName). Re-checked here. */
    displayName?: unknown;
  } | null;
  if (orgPayload?.orgAgent && orgPayload.person) {
    const person = orgPayload.person.toLowerCase();
    const org = orgPayload.orgAgent.toLowerCase();
    const existing = JSON.parse((await env.AUTH_CODES.get(`related:${person}:${org}`)) ?? '{}') as Record<string, unknown>;
    const link = {
      ...existing,
      orgAgent: orgPayload.orgAgent,
      orgName: orgPayload.orgName || existing.orgName || '',
      purpose: orgPayload.purpose ?? existing.purpose ?? 'related-org',
      requestedBy: grant.client_id,
      siteDelegation: body.delegation ?? existing.siteDelegation ?? null,
      brokerDelegation: orgPayload.brokerDelegation ?? existing.brokerDelegation ?? null,
      // spec 246 — person↔org read delegations: membership (person→org, org reads its
      // member) + stewardship (org→person, person reads/oversees the org).
      // MERGE: a workspace-create already wrote the stewardship wire; do not null it.
      membershipDelegation: orgPayload.membershipDelegation ?? existing.membershipDelegation ?? null,
      stewardshipDelegation: orgPayload.stewardshipDelegation ?? existing.stewardshipDelegation ?? null,
      // The org → app-service-agent Operational Intent grant, when the app declared a service SA.
      // Persisted here because the ceremony is the only moment it exists: minted into the deploy
      // batch, handed back once, and otherwise lost.
      operationalDelegation: orgPayload.operationalDelegation ?? existing.operationalDelegation ?? null,
      // The org → app-workspace READ grant (whitelabel org_read_grant) — persisted for the same
      // reason: minted only at the ceremony, and its random salt makes an unreturned body unusable.
      readGrantDelegation: orgPayload.readGrantDelegation ?? existing.readGrantDelegation ?? null,
      proofHash: orgPayload.proofHash ?? existing.proofHash ?? null,
      credential: orgPayload.credential ?? existing.credential ?? null,
      kind:
        orgPayload.kind ??
        existing.kind ??
        (orgPayload.purpose === 'field-workspace' ? 'workspace' : orgPayload.purpose === 'field-team' ? 'team' : orgPayload.purpose === 'field-circle' ? 'circle' : orgPayload.purpose === 'field-church' ? 'church' : 'org'),
      parent: orgPayload.parent ?? existing.parent ?? person,
      // The governor rides the link so the invite ceremony can find it without a vault read (`lib/workspace-governor.ts`).
      ...(orgPayload.governor ? { governor: String(orgPayload.governor).toLowerCase() } : existing.governor ? { governor: existing.governor } : {}),
      // The organization's type rides the link for Admin's count (org.profile in the org's vault is the record).
      ...(checkOrgType(orgPayload.orgType) ? { orgType: checkOrgType(orgPayload.orgType) } : existing.orgType ? { orgType: existing.orgType } : {}),
      // Its display name, for Admin's list (org.profile is the record); the handle stays in orgName.
      ...(checkOrgDisplayName(orgPayload.displayName) ? { displayName: checkOrgDisplayName(orgPayload.displayName) } : existing.displayName ? { displayName: existing.displayName } : {}),
      createdAt: existing.createdAt ?? Date.now(),
    };
    await env.AUTH_CODES.put(`related:${person}:${org}`, JSON.stringify(link));
    // The organization's contact email starts as this person's verified one, if it has none yet (org-contact.ts).
    // Organizations only: not a workspace, not a person's own name, not a membership.
    if (link.kind !== 'workspace' && link.kind !== 'person' && (existing.relationship ?? '') !== 'member') {
      await (operatorOrg(env) ? recordOrgDefault(env, request, person, org, link.stewardshipDelegation) : defaultOrgContact(env, person, org));
    }
    const idxKey = `related-idx:${person}`;
    const idx = JSON.parse((await env.AUTH_CODES.get(idxKey)) ?? '[]') as string[];
    if (!idx.includes(org)) { idx.push(org); await env.AUTH_CODES.put(idxKey, JSON.stringify(idx)); }
    const bd = orgPayload.brokerDelegation;
    if (bd?.delegate) {
      const dKey = `delegated-idx:${bd.delegate.toLowerCase()}`;
      const dIdx = JSON.parse((await env.AUTH_CODES.get(dKey)) ?? '[]') as Array<{ orgAgent: string; orgName: string; delegation: unknown }>;
      if (!dIdx.some((x) => x.orgAgent.toLowerCase() === org)) {
        dIdx.push({ orgAgent: orgPayload.orgAgent, orgName: orgPayload.orgName ?? '', delegation: bd });
        await env.AUTH_CODES.put(dKey, JSON.stringify(dIdx));
      }
    }
  }

  // Spec 397 W4 — A PERSON-LEVEL APP GRANT (the Home MCP's `ask-as-me` and any template that is the person's own wire to
  // an app, not an organization's): indexed here by person so Connected Apps can show it and REVOKE it on chain. The
  // wire is the record (held by the app, revocable on chain); this row is a rebuildable pointer (ADR-0055).
  if (!body.org && body.delegation?.delegator) {
    const person = String(body.delegation.delegator).toLowerCase();
    const key = `app-grants:${person}`;
    const rows = JSON.parse((await env.AUTH_CODES.get(key)) ?? '[]') as Array<{ clientId: string }>;
    const next = rows.filter((r) => r.clientId !== grant.client_id);
    next.unshift({ clientId: grant.client_id, template: grant.delegation_template, delegate: grant.delegate, delegation: body.delegation, issuedAt: Date.now(), ...(actTemplate ? { wires: body.delegations } : {}) } as never);
    await env.AUTH_CODES.put(key, JSON.stringify(next.slice(0, 50)));
  }

  // Stash the grant under a single-use code, BOUND to the PKCE challenge + client + redirect.
  const code = newAuthCode();
  await env.AUTH_CODES.put(
    `oidc:${code}`,
    JSON.stringify({
      id_token: idToken,
      delegation: body.delegation,
      sessionDelegation: body.sessionDelegation ?? null,
      paymentDelegation: body.paymentDelegation ?? null,
      pullDelegation: body.pullDelegation ?? null,
      settlementHash: body.settlementHash ?? null,
      treasury: body.treasury ?? null,
      selfVaultGrant: body.selfVaultGrant ?? null,
      delegations: actTemplate ? body.delegations : null,
      org: body.org ?? null,
      // Returned verbatim by /token so an app can read the HUMAN name explicitly rather than
      // inferring it from `agent_name`. '' (never absent) when the client isn't `profile`-scoped.
      profile_name: profileName,
      code_challenge: grant.code_challenge,
      client_id: grant.client_id,
      redirect_uri: grant.redirect_uri,
    }),
    { expirationTtl: Math.ceil(CODE_TTL_MS / 1000) },
  );
  return json({ code });
};
