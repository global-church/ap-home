// The onboarding ACTIVITIES as first-class operations, named in the member's lexicon
// (docs/portal-lexicon.md). Each wraps the lower-level connect-client primitives so the flow
// reads as the ontology — secure → register → permit — not deploy/claim/delegate.
//
// A member secures + opens their home with one of several CREDENTIALS (`Via`): a passkey
// (this device), a wallet (SIWE/EOA custodian), or Google (a per-subject KMS-derived custodian
// the server signs with — see spec 235). The operations are via-parameterized so the journey
// branches on the chosen credential.
import { assignDefaultArchetype } from './default-archetype';
import type { Address, Hex } from '@agenticprimitives/types';
import { keccak256, toBytes } from 'viem';
import { fastPollMs } from '../lib/fast-poll';
import {
  createSecureHomePasskey,
  deployAndClaimAgent,
  connectWithName,
  createChildAgentForSite,
  createOrganizationWithGoogle,
  signupWithName,
  signupWalletNoName,
  passkeySignHash,
  googleSignHash,
  connectCustodianCached,
  approveGrantHashes,
  secureHomeWithGoogle,
  secureHomeGoogleNoName,
  chargePayment,
  collectSubscriptions,
  claimName,
  setConnectionInfo,
  isAgentDeployed,
  derivePasskeySa,
  createManagedAgent,
  invalidateRelatedOrgs,
  AUD,
  type SignHash,
} from '../connect-client';
import { writeGovernancePair, WORKSPACE_CONTENT_SCOPE } from '../lib/workspace-governor';
import type { ConnectionKind } from '@agenticprimitives/agent-naming';
import { startGoogleSignIn, startYouVersionSignIn } from '../server-client';
import { writePendingEnrollJson } from '../components/onboarding/pending-enroll';
import { nameLabel } from '../lib/domain';
import { mandateDelegate } from '../lib/new-member';
import { connectWallet, personalSign } from '../lib/wallet';
import { isDemoCustodyHome, demoCustodySignHash } from '../lib/persona-custody';
import { writeOrganizationMembership } from '../lib/membership-write';
import { getClient } from '../lib/oidc-clients';
import { issueSelfVaultGrant, buildApprovedSiteDelegation, buildApprovedOperationalIntentDelegation, buildApprovedOrgReadDelegation, issueOrgReadDelegation, buildApprovedSelfVaultGrant, buildApprovedSessionDelegation, buildApprovedInboxDeliveryDelegation, buildApprovedInteractionsDelegation, issueSessionDelegation, issueSiteDelegation, issuePaymentDelegation, issueInboxDeliveryDelegation, issueInteractionsDelegation, issueServiceAgentWireDelegation, OPEN_DELEGATION, ORG_INTERACTIONS_SESSION_LEAF_TTL_SECONDS, ORG_INTERACTIONS_SESSION_LEAF_LADDER_RUNGS, PERSON_INTERACTIONS_SESSION_LEAF_TTL_SECONDS, toWire, buildVaultKeyAuthorization, APPROVED_HASH_SENTINEL, type DelegationWire, type SelfVaultGrantConfig, type VaultKeyCeremonyParams } from '../lib/delegation';
import { vaultWriteWithDelegation, vaultReadWithDelegation } from '../lib/vault-client';
import { saveStandingGrant, loadStandingGrant, saveStandingGrantWithSelfVault, loadStandingGrantWithSelfVault } from '../lib/grant-cache';
import { DELIVERY_SERVICE_SA, INTERACTIONS_SERVICE_SA, MCP_SERVER_ID } from '../lib/inbox-delivery';
import { ensureCsrfToken, csrfHeaders } from '../csrf';
import type { DemoPasskey } from '../lib/passkey';
import { readSsoCookie } from '../lib/sso-cookie';
import { SESSION_KEY } from '../context/session';
import type { Home } from './types';
import { homeLabel } from './types';
import { provisionsAgentPlaybook, provisionsCommunityMessaging } from '../whitelabel/provisioning';
import type { OrgTypeV1 } from '../lib/org-type';

/** The person's Home session Bearer, from wherever it lives (explicit auth → this-origin localStorage →
 *  parent-domain SSO cookie) — session-gated /connect endpoints (e.g. the naming + membership stores)
 *  reject without it, and NOT every caller threads `auth` (passkey flows pass none). */
function storedSessionToken(auth?: Auth): string | null {
  if (auth?.token) return auth.token;
  return homeBearerToken();
}

/** The BROKER home-session token (localStorage/cookie) — what `/connect/*` and the InteractionsDO
 *  session gate verify. NEVER the custody-session `auth.token`: for the phone/email family that is
 *  a demo-a2a custody token with a different audience, and home-gated endpoints 401 on it (the
 *  org-create #general + relationships writes failed exactly this way for phone homes). */
function homeBearerToken(auth?: Auth): string | null {
  try {
    const raw = localStorage.getItem(SESSION_KEY);
    const t = raw ? (JSON.parse(raw) as { token?: string }).token : undefined;
    if (t) return t;
  } catch { /* fall through */ }
  return readSsoCookie()?.token ?? auth?.token ?? null;
}

export type Via = 'passkey' | 'wallet' | 'google' | 'youversion' | 'email' | 'phone';
/** Extra auth a server-custodied op needs: the custody session token demo-a2a verifies. */
export type Auth = { token: string };
type Result<T> = ({ ok: true } & T) | { ok: false; error: string };

/** OIDC credentials that are KMS-custodied server-side (demo-a2a derives the custodian from the
 *  session's (iss, sub) — spec 235). Both sign + recover with no device gesture, unlike passkey/wallet.
 *  The signer path (`signHashFor`), org-create, and the recognized-connect grant all branch on this. */
export function isKmsVia(via: Via): boolean {
  via = (String(via ?? '').toLowerCase() as Via); // tolerate the 'Google'/'YouVersion' display form the session stores
  // `email` + `phone` join the KMS family (email/phone-bootstrap): a verified email/phone with no home of
  // its own gets a per-subject KMS-custodied home (iss='email'|'phone', sub=SHA-256(value)) — the same
  // server-side C_sub signing as Google.
  return via === 'google' || via === 'youversion' || via === 'email' || via === 'phone';
}

/**
 * Resolve the credential to SIGN with for an agent. Prefer the agent's ACTUAL on-chain custody
 * credential (`BasicProfile.credential`) over the session/cookie `via` — the cookie `via` defaults
 * to `passkey` and would wrongly trigger a WebAuthn prompt for a Google/social-custodied agent (which
 * has no passkey). Mirrors RecognizedEnroll's resolver so every signing surface routes custody the
 * same way. Falls back to the cookie `via`, then `passkey`.
 */
export function resolveVia(credential: string | undefined, cookieVia: string | undefined): Via {
  const c = (credential || '').toLowerCase();
  const v = (cookieVia || '').toLowerCase();
  if (c.includes('passkey')) return 'passkey';
  if (c.includes('siwe') || c.includes('eoa') || c.includes('wallet') || c.includes('hardware')) return 'wallet';
  if (c.includes('youversion')) return 'youversion';
  if (c.includes('google')) return 'google';
  // A Google/YouVersion session's credential kind is `'oidc'` (server-side KMS custody — see
  // server/oidc/{google,youversion}/callback.ts). Both sign via KMS using the session token (the
  // custodian is derived server-side from the session's iss/sub), so map `oidc`/`kms` to a KMS via —
  // distinguishing the label by the cookie via, defaulting to google. This is what stops a social
  // agent from being mis-routed to a (nonexistent) passkey.
  if (c.includes('email')) return 'email';
  if (c.includes('phone')) return 'phone';
  // An email/phone-bootstrapped home shares the `oidc`/`kms` on-chain credential with Google (same C_sub
  // mechanism); the cookie `via` disambiguates the label + KMS provider.
  if (c.includes('oidc') || c.includes('kms')) return v === 'youversion' ? 'youversion' : v === 'email' ? 'email' : v === 'phone' ? 'phone' : 'google';
  return v === 'wallet' || v === 'google' || v === 'youversion' || v === 'email' || v === 'phone' || v === 'passkey' ? (v as Via) : 'passkey';
}

/** ①a — your device becomes your key (passkey path only; wallet/Google have no create step). */
export async function createHomeKey(name: string): Promise<DemoPasskey> {
  return createSecureHomePasskey(name);
}

/**
 * Begin Google sign-in for the Personal Home (a full-page redirect out to the broker, then back
 * to `?code`). A preferred name is stashed so the post-redirect secure-home step (GoogleSecureHome)
 * can offer it — the SA itself is derived from the Google identity, not the name. Used by both the
 * entry screen and the onboarding journey, so it lives here (no component cycle).
 */
export function continueWithGoogle(preferredName?: string, enrollStashJson?: string): void {
  try {
    if (preferredName) sessionStorage.setItem('pendingHomeName', preferredName);
    // Relying-app enrollment stashes its request here so the post-redirect resume can finish +
    // return the code; self-serve CLEARS any stale stash so it doesn't hijack a plain sign-in.
    writePendingEnrollJson(enrollStashJson);
  } catch {
    /* storage blocked — the secure-home step will just ask for a name */
  }
  startGoogleSignIn(AUD, window.location.origin + '/');
}

/** Begin YouVersion sign-in for the Personal Home — identical to {@link continueWithGoogle} (full-page
 *  redirect out to the broker, back to `?code&via=youversion`). YouVersion is KMS-custodied like Google,
 *  so the post-redirect resume + secure-home steps are shared; only the IdP differs. */
export function continueWithYouVersion(preferredName?: string, enrollStashJson?: string): void {
  try {
    if (preferredName) sessionStorage.setItem('pendingHomeName', preferredName);
    writePendingEnrollJson(enrollStashJson);
  } catch {
    /* storage blocked — the secure-home step will just ask for a name */
  }
  startYouVersionSignIn(AUD, window.location.origin + '/');
}

/**
 * ① + ② — Secure a home with your name, with the chosen credential. The name claim must come
 * FROM the member's own Smart Agent (the subregistry is one-name-per-caller), so it's a signed
 * userOp from the custodian:
 *   passkey → deploy + claim signed by the just-created passkey (`key`).
 *   wallet  → deploy (EOA-custodied) + claim signed by the EOA (signupWithName).
 *   google  → handled by the server (the per-subject KMS custodian signs) — wired in spec 235.
 */
/**
 * Device-via (passkey/wallet) fast path — build the person's interactions + inbox-delivery grants as
 * `0x03` approved-hash wires so their digests can be pre-approved INSIDE the deploy userOp (spec 253),
 * exactly like org-create batches its outbound grants. Returns the digests to fold into the deploy +
 * `submit()` that hands the pre-approved wires to the DOs AFTER the deploy is RPC-visible. This removes
 * TWO device signatures (interactions + delivery) — they ride the single deploy prompt instead. KMS vias
 * (google/youversion/email/phone) NEVER take this path — they stay on the silent server-signed
 * `activatePersonPlanes`, so nothing changes for them (already zero device prompts). Inert grants
 * (service SA unset) are skipped, same as the per-grant path.
 */
async function buildBatchedPersonPlaneGrants(sa: Address): Promise<{ digests: Hex[]; vaultFolded: boolean; submit: () => Promise<void> }> {
  const digests: Hex[] = [];
  const posts: Array<() => Promise<void>> = [];
  const low = sa.toLowerCase();
  if (INTERACTIONS_SERVICE_SA) {
    const ix = buildApprovedInteractionsDelegation(sa, INTERACTIONS_SERVICE_SA, MCP_SERVER_ID);
    digests.push(ix.digest);
    let leafWire: DelegationWire | undefined;
    try {
      const sk = (await fetch(`/a2a/agent/interactions-session-key`).then((r) => r.json()).catch(() => null)) as { ok?: boolean; address?: string } | null;
      if (sk?.ok && sk.address && /^0x[0-9a-fA-F]{40}$/.test(sk.address)) {
        const leaf = buildApprovedSessionDelegation(sa, sk.address as Address, [INTERACTIONS_SERVICE_SA, ...(DELIVERY_SERVICE_SA ? [DELIVERY_SERVICE_SA] : [])]); // spec 408 §2.1
        digests.push(leaf.digest);
        leafWire = toWire(leaf.delegation);
      }
    } catch { /* no interactions-session key → DO uses the server-mint bridge; the grant still lands */ }
    posts.push(async () => {
      await ensureCsrfToken();
      const res = await fetch(`/a2a/interactions/${low}/grant`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'content-type': 'application/json', ...csrfHeaders() },
        body: JSON.stringify({ delegation: toWire(ix.delegation), ...(leafWire ? { sessionLeaf: leafWire } : {}) }),
      });
      const data = (await res.json().catch(() => ({}))) as { ok?: boolean; error?: string };
      if (!res.ok || data.ok !== true) throw new Error(data.error ?? `interactions grant store failed (HTTP ${res.status})`);
    });
  }
  if (DELIVERY_SERVICE_SA) {
    const dl = buildApprovedInboxDeliveryDelegation(sa, DELIVERY_SERVICE_SA, MCP_SERVER_ID);
    digests.push(dl.digest);
    posts.push(async () => {
      const res = await fetch(`/a2a/interactions/${low}/grant.delivery.put`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ delegation: toWire(dl.delegation) }),
      });
      const data = (await res.json().catch(() => ({}))) as { ok?: boolean; error?: string };
      if (!res.ok || data.ok !== true) throw new Error(data.error ?? `delivery grant store failed (HTTP ${res.status})`);
    });
  }
  // VAULT-KEY fold (Phase B) — pre-derive the DETERMINISTIC KEK ref from server-info, build the vault-key
  // authorization as a 0x03 wire + the provision-challenge, and pre-approve BOTH digests in the deploy.
  // submit() then provisions (proof=0x03) + binds (0x03 wire) with NO separate signature. Skipped (caller
  // falls back to activateVaultIfNeeded) when server-info has no kmsKeyRef (GCP env unset / demo-mcp not yet
  // deployed with the deterministic-ref change) — no regression.
  let vaultFolded = false;
  try {
    const info = (await fetch(`/mcp-bind/custody/vault-key/server-info?owner=${low}`).then((r) => r.json())) as {
      serverId?: string; serverKey?: string; kmsKeyRef?: string | null; defaultResources?: string[]; classificationCeiling?: string; ops?: ('read' | 'write')[];
    };
    if (info?.kmsKeyRef) {
      const params: VaultKeyCeremonyParams = {
        vaultId: info.serverId ?? MCP_SERVER_ID,
        kmsKeyRef: info.kmsKeyRef,
        serverKey: (info.serverKey ?? '0x0000000000000000000000000000000000000001') as Address,
        allowedResources: info.defaultResources ?? ['person-pii', 'org-sensitive', 'profile', 'vault:*'],
        classificationCeiling: info.classificationCeiling ?? 'regulated.high',
        ops: info.ops ?? ['read', 'write'],
      };
      const vk = buildVaultKeyAuthorization(sa, params);
      vk.delegation.signature = APPROVED_HASH_SENTINEL;
      digests.push(vk.digest);
      const issuedAt = Math.floor(Date.now() / 1000);
      const provChallenge = keccak256(toBytes(['demo-mcp:vault-key-provision:v1', low, String(issuedAt)].join('\n')));
      digests.push(provChallenge);
      posts.push(async () => {
        const pr = await fetch('/mcp-bind/custody/vault-key/provision', {
          method: 'POST', headers: { 'content-type': 'application/json' },
          // owner MUST be lowercase to match the deterministic kmsKeyRef server-info computed (also from the
          // lowercase owner). executeGcpProvision mints the KEK at sanitizeKeyId(owner) — a checksummed `sa`
          // here would mint a MIXED-CASE key path while the binding stores the lowercase one → vault ops 404.
          body: JSON.stringify({ owner: low, issuedAt, proof: APPROVED_HASH_SENTINEL }),
        });
        const pd = (await pr.json().catch(() => ({}))) as { ok?: boolean; error_description?: string; detail?: string };
        if (!pr.ok || pd.ok !== true) throw new Error(pd.error_description ?? pd.detail ?? `vault provision failed (HTTP ${pr.status})`);
        const br = await fetch('/mcp-bind/custody/vault-key/bind', {
          method: 'POST', headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ owner: sa, vaultId: params.vaultId, kmsKeyRef: params.kmsKeyRef, allowedResources: params.allowedResources, classificationCeiling: params.classificationCeiling, ops: params.ops, expiresAt: vk.expiresAt, authorization: toWire(vk.delegation) }),
        });
        const bd = (await br.json().catch(() => ({}))) as { ok?: boolean; reason?: string; error?: string };
        if (!br.ok || bd.ok !== true) throw new Error(bd.reason ?? bd.error ?? `vault-key bind failed (HTTP ${br.status})`);
      });
      vaultFolded = true;
    }
  } catch (e) { console.warn('[home-create] vault-key fold skipped (falling back to signed bind):', e); vaultFolded = false; }
  return {
    digests,
    vaultFolded,
    submit: async () => { for (const p of posts) { try { await p(); } catch (e) { console.warn('[home-create] plane wire submit deferred (recover via Enable-messaging):', e); } } },
  };
}
/**
 * spec 323 — front-load EVERY person-plane capability at home creation, so the member never meets a
 * cold "activate your vault key / enable storage" prompt later (profile save, inbox, channels all
 * need these). Vault-key bind + inbox-delivery + interactions plane, in order. KMS family
 * (google/email/phone) = ZERO device prompts (server-signed); passkey/wallet = the vault-key bind is
 * ONE signature at creation (better than a surprise prompt on first profile save — value steps ≠
 * signatures, but this IS the value step). All idempotent + best-effort: a failure never blocks the
 * home from coming up (the per-surface Enable paths remain the recovery).
 */
async function activatePersonPlanes(owner: Address, via: Via, auth?: Auth): Promise<void> {
  try {
    // DEPLOY-VS-GRANT RACE: every plane grant (vault-key, inbox-delivery, interactions) is verified
    // on-chain against the principal's SA via ERC-1271. If the deploy userOp hasn't confirmed on the RPC
    // the InteractionsDO reads, that verification reverts and the grant 403s ("signature failed
    // verification against the delegator") — leaving the member with NO messaging plane, so they can
    // neither send nor RECEIVE DMs (a delivered invite silently 409s at the recipient's DO). Wait,
    // bounded, for the SA to actually be deployed before provisioning. KMS/server-deployed homes pass
    // this immediately; wallet/passkey homes whose deploy op is still mining wait it out.
    for (let i = 0; i < 20; i++) {
      if (await isAgentDeployed(owner).catch(() => false)) break;
      await new Promise((r) => setTimeout(r, fastPollMs(2000)));
    }
    const bound = await activateVaultIfNeeded(owner, via, auth); // also fires inbox-delivery
    // The interactions (messaging) plane is INDEPENDENT of the vault-key bind — a delegation to the
    // interactions service SA, not a vault write. A vault-key hiccup must NOT skip it, or the member is
    // left permanently unable to SEND any person→person DM (send 409s "no interactions grant") with no
    // recovery but the manual Enable-messaging path. Attempt both; each is best-effort + idempotent.
    if (!bound.ok) console.warn('[home-create] vault key not activated (activate it later from Security):', bound.error);
    const ix = await activateInteractionsIfNeeded(owner, via, auth);
    if (!ix.ok) console.warn('[home-create] interactions plane not enabled (enable later):', ix.error);
  } catch (e) {
    console.warn('[home-create] person-plane activation deferred:', e);
  }
}

/**
 * spec 280 carve-out — publish a SOCIAL home's connection KIND (google/youversion) onto its PUBLIC name
 * node, so a returning member can sign in on a FRESH device (no session cookie). The returning name-path
 * sign-in (`EntryExperience`) reads `connectionKind` (via `/connect/name-info`) to offer "Continue with
 * Google/YouVersion"; without it, `connectionKind` is null AND the KMS `C_sub` counts as an EOA
 * (`hasEoa=true`), so the screen mis-offers "Continue with wallet" and the social member is locked out.
 *
 * Reconciles with the "never call setConnectionInfo automatically" doctrine (opt-in bootstrap carve-out):
 * KIND ONLY — never the address (the real linkability risk stays opt-in); owner-authorized (the C_sub
 * signs, gaslessly, no gesture); necessary-for-function (cross-device return of a social home). Idempotent
 * (skips when the kind is already published) + best-effort (never blocks onboarding). Non-social vias and
 * nameless homes are no-ops.
 */
export async function publishSocialConnectionKindIfNeeded(agent: Address, name: string, via: Via, auth?: Auth): Promise<void> {
  if (via !== 'google' && via !== 'youversion') return;
  if (!name || !nameLabel(name)) return; // a nameless home has no name node to write
  try {
    // Idempotency: read the SAME record the returning sign-in reads; skip the on-chain write if it's set.
    const info = (await fetch(`/connect/name-info?name=${encodeURIComponent(name)}`)
      .then((r) => r.json())
      .catch(() => ({}))) as { connectionKind?: string | null };
    if (info?.connectionKind === via) return;
    const signHash = await signHashFor(via, agent, auth);
    await setConnectionInfo(agent, name, via as ConnectionKind, signHash); // KIND only — never the address
  } catch (e) {
    console.warn('[connection-kind] social publish deferred (retry from Naming):', e);
  }
}

/** THE AGENT IS BORN WITH ITS PLAYBOOK (spec 354 §3 / K3), on EVERY onboarding path — Google, passkey, wallet, no-name.
 *  Best-effort and last: an unassigned agent runs the bare harness, which works; failing an enrolment because a
 *  BEHAVIOUR could not be attached would be the tail wagging the dog, and behaviour grants nothing. */
async function bornWithPlaybook(agent: string, auth?: Auth): Promise<void> {
  // A client that opted out of the playbook (Gather27, provisioning.agentPlaybook: false) does not get one at
  // birth either (Paul, 2026-10-15: the first sign-in fetched it from a skills registry GC does not run, and the
  // console filled with its CORS error). Same rule, same source, as the self-heal in context/session.tsx.
  const askedBy = typeof window === 'undefined' ? undefined : (new URL(window.location.href).searchParams.get('client_id') ?? undefined);
  if (!provisionsAgentPlaybook(askedBy)) return;
  try {
    const token = homeBearerToken(auth);
    if (!token) { console.warn('[home-create] default archetype deferred: no session yet (assign from Behaviour → Playbook)'); return; }
    const a = await assignDefaultArchetype(agent, 'person', token);
    if (!a.ok) console.warn('[home-create] default archetype not assigned (the bare harness stands):', a.reason);
  } catch (e) { console.warn('[home-create] default archetype deferred:', e); }
}

export async function secureHome(
  key: DemoPasskey | null,
  name: string,
  via: Via = 'passkey',
  auth?: Auth,
  onStep?: (s: string) => void,
): Promise<Result<{ home: Home }>> {
  if (via === 'google') {
    // Server custody: demo-a2a derives C_sub + deploys + claims, gated by the custody session.
    if (!auth?.token) return { ok: false, error: 'no custody session' };
    const out = await secureHomeWithGoogle(auth.token, homeLabel(name));
    if (!out.ok) return { ok: false, error: out.error };
    await activatePersonPlanes(out.agent, via, auth);
    // THE AGENT IS BORN WITH ITS PLAYBOOK (spec 354 §3). A person's own agent is the surface the Ask runs
    // on; without an assignment every capability it offers comes from hardcoded tool declarations and the
    // contracts a domain author wrote never reach it. Best-effort and last: an unassigned agent runs the
    // bare harness, which works — failing an enrolment because a BEHAVIOUR could not be attached would be
    // the tail wagging the dog, and behaviour grants nothing.
    await bornWithPlaybook(out.agent, auth);
    return { ok: true, home: { address: out.agent, name: out.name } };
  }
  if (via === 'wallet') {
    // WALLET fast path — batch interactions + inbox-delivery into the deploy userOp (one wallet prompt),
    // then bind the vault key. Only the FRESH-EOA deploy honors the callback; a returning EOA agent has no
    // deploy op to batch into, so `batched` stays false and we take the proven per-grant path (no regression).
    let batched = false;
    let vaultFolded = false;
    const out = await signupWithName(homeLabel(name), 'wallet', undefined, false, async (sa) => {
      batched = true;
      const g = await buildBatchedPersonPlaneGrants(sa);
      vaultFolded = g.vaultFolded;
      return g;
    });
    if (!out.ok) return { ok: false, error: out.error };
    if (!batched) {
      await activatePersonPlanes(out.agent, via, auth);
    } else if (!vaultFolded) {
      try { const bound = await activateVaultIfNeeded(out.agent, via, auth); if (!bound.ok) console.warn('[home-create] vault key not activated (activate later from Security):', bound.error); }
      catch (e) { console.warn('[home-create] vault-key activation deferred:', e); }
    }
    await bornWithPlaybook(out.agent, auth);
    return { ok: true, home: { address: out.agent, name: out.name } };
  }
  if (!key) return { ok: false, error: 'no key for this device' };
  // PASSKEY fast path — pre-derive the SA, build interactions + inbox-delivery as 0x03 wires, and
  // deploy + claim + approve ALL their digests in ONE userOp (one passkey prompt) instead of signing each
  // grant separately. Then hand the pre-approved wires to the DOs (no prompt) and bind the vault key. If
  // the SA can't be pre-derived, fall back to the proven per-grant path (no regression).
  const sa = await derivePasskeySa(key, 0n).catch(() => null);
  const planes = sa ? await buildBatchedPersonPlaneGrants(sa).catch(() => null) : null;
  const res = await deployAndClaimAgent(key, homeLabel(name), planes?.digests ?? [], onStep);
  if (!res.ok) return { ok: false, error: res.error };
  if (planes && sa && res.agent.toLowerCase() === sa.toLowerCase()) {
    // Wait for the deploy to be RPC-visible so the DOs can verify the 0x03 wires against the approved
    // hashes set INSIDE the deploy batch, then hand them over (no signature). Vault-key still binds via
    // activateVaultIfNeeded for now (Phase B folds it into the deploy too).
    for (let i = 0; i < 20; i++) { if (await isAgentDeployed(res.agent).catch(() => false)) break; await new Promise((r) => setTimeout(r, fastPollMs(2000))); }
    await planes.submit();
    if (!planes.vaultFolded) {
      try { const bound = await activateVaultIfNeeded(res.agent, via, auth); if (!bound.ok) console.warn('[home-create] vault key not activated (activate later from Security):', bound.error); }
      catch (e) { console.warn('[home-create] vault-key activation deferred:', e); }
    }
  } else {
    await activatePersonPlanes(res.agent, via, auth);
  }
  await bornWithPlaybook(res.agent, auth);
  return { ok: true, home: { address: res.agent, name: res.name } };
}

/**
 * spec 257 Phase 1.5 — TRUE name-deferral (Google only). Secure a home with NO name: the server
 * deploys the member's KMS-custodied SA with empty callData, leaving their single subregistry slot
 * FREE. The member is name-free after onboarding and claims a public handle LATER, by choice, via
 * the portal's ClaimPublicNameCard (`claimName`). Returns a home with an empty `name`.
 */
export async function secureHomeNoName(auth?: Auth, opts: { claimPendingNameVia?: Via } = {}): Promise<Result<{ home: Home }>> {
  if (!auth?.token) return { ok: false, error: 'no custody session' };
  const out = await secureHomeGoogleNoName(auth.token);
  if (!out.ok) return { ok: false, error: out.error };
  // OPT-IN (email/phone cards only — the Google flows consume `pendingHomeName` themselves): a member
  // who CHOSE a name before securing with email/phone (the journey's contact screen stashes it exactly
  // like the Google redirect does) gets it claimed here — KMS-signed, zero prompts. Without this the
  // chosen name was silently dropped and the home came out nameless (rich-phone3, 2026-07-10).
  let claimed = '';
  if (opts.claimPendingNameVia) {
    try {
      const pending = sessionStorage.getItem('pendingHomeName');
      if (pending) {
        sessionStorage.removeItem('pendingHomeName');
        const label = nameLabel(pending);
        if (label) {
          const signHash = await signHashFor(opts.claimPendingNameVia, out.agent, auth);
          const res = await claimName(out.agent, signHash, label);
          if (res.ok) claimed = res.name;
          else console.warn('[secure-home] chosen name not claimed (claim it from the Naming page):', res.error);
        }
      }
    } catch (e) {
      console.warn('[secure-home] chosen name not claimed (claim it from the Naming page):', e);
    }
  }
  await activatePersonPlanes(out.agent, opts.claimPendingNameVia ?? 'google', auth);
  await bornWithPlaybook(out.agent, auth);
  return { ok: true, home: { address: out.agent, name: claimed } };
}

/** Secure a NAMELESS home with a WALLET — the door's "Continue with a wallet" for an EOA that has no home yet.
 *  Mirrors the wallet branch of `secureHome` with no name: the plane grants fold into the deploy userOp (one
 *  wallet prompt), the vault key binds unless it was folded, the agent is born with its playbook, and the
 *  session comes back from the SIWE sign-in. The public name is claimed later, by choice (ADR-0013: one
 *  mechanism — deploy nameless, claim on demand). */
export async function secureHomeWalletNoName(onStep?: (s: string) => void): Promise<Result<{ token: string; home: Home; fresh: boolean }>> {
  let batched = false;
  let vaultFolded = false;
  const out = await signupWalletNoName(onStep, async (sa) => {
    batched = true;
    const g = await buildBatchedPersonPlaneGrants(sa);
    vaultFolded = g.vaultFolded;
    return g;
  });
  if (!out.ok) return { ok: false, error: out.error };
  const auth: Auth = { token: out.token };
  if (out.fresh) {
    if (!batched) {
      await activatePersonPlanes(out.agent, 'wallet', auth);
    } else if (!vaultFolded) {
      try { const bound = await activateVaultIfNeeded(out.agent, 'wallet', auth); if (!bound.ok) console.warn('[home-create] vault key not activated (activate later from Security):', bound.error); }
      catch (e) { console.warn('[home-create] vault-key activation deferred:', e); }
    }
    await bornWithPlaybook(out.agent, auth);
  }
  return { ok: true, token: out.token, home: { address: out.agent, name: '' }, fresh: out.fresh };
}

/** Open your home from this device (prove it's you → a session). `via` = the credential. */
export async function openHome(
  name: string,
  via: 'passkey' | 'wallet' = 'passkey',
  opts: { passkeyMode?: 'local' | 'discoverable' } = {},
): Promise<Result<{ token: string }>> {
  const out = await connectWithName(name, via, opts);
  return out.ok ? { ok: true, token: out.token } : { ok: false, error: out.error };
}

/** The signer for an on-behalf action (delegation / userOp), chosen by credential. `sender` is
 *  the SA the signature is for (needed by the Google server-signer to derive + scope C_sub).
 *  Exported so portal surfaces (e.g. the spec-257 W4 "Claim your public name" card) can sign a
 *  userOp with the member's CURRENT credential without re-deriving the signer logic. */
export async function signHashFor(via: Via, sender?: Address, auth?: Auth): Promise<SignHash> {
  via = (String(via ?? '').toLowerCase() || 'passkey') as Via; // tolerate the display-form via from the session
  if (via === 'wallet') {
    // DEMO ACCOUNTS FIRST: a seeded demo person (Nathan, David…) has a wallet CREDENTIAL but no
    // wallet in this browser — their custodian key is held by the Home (DEMO_PERSONA_KEYS). Signing
    // server-side gives them the same prompt-free ceremonies a KMS home has; every real wallet home
    // probes `false` once per session and falls straight through to the injected provider below.
    if (auth?.token && (await isDemoCustodyHome(auth.token))) return demoCustodySignHash(auth.token);
    // Sign with the wallet that CUSTODIES `sender` (the home SA) — not MetaMask's active account (which
    // may be another home's custodian, e.g. the platform deployer). This is the relying-app GRANT signer,
    // so the site/session/payment delegations must be signed by the home's actual custodian. Falls back to
    // the active account only when no sender is known (shouldn't happen on the grant path).
    // B5 — cache-first: reuse the session custodian (seeded at SIWE/bootstrap) without re-popping the picker.
    const addr = sender ? await connectCustodianCached(sender) : await connectWallet(true);
    return (h: Hex) => personalSign(addr, h);
  }
  if (isKmsVia(via)) {
    if (!sender || !auth?.token) throw new Error('granting with an OIDC home needs a custody session');
    return googleSignHash(sender, auth.token); // demo-a2a signs with the per-(iss,sub) KMS custodian
  }
  return passkeySignHash;
}

/** uupg interop (ported from the GC impact home) — PROJECT the steward relationship into the person's
 *  `impact-relationships` VAULT record. The authoritative store is the interactions-plane relationships
 *  doc (spec 323 W1 — merged in createOrganization below); this vault record is a PROJECTION for relying
 *  apps (the uupg tracker) that discover "orgs you steward" + the acting grants from the person's vault
 *  via their site-login delegation. Merge-by-agent: a re-create never clobbers grants it doesn't carry
 *  (same upsert semantics as impact's relationships-store). Best effort — a failed projection never
 *  fails the ceremony (the relying app can self-heal the record from its own org-create return). */
async function projectStewardRelationshipToVault(
  person: Address,
  via: Via,
  auth: Auth | undefined,
  org: { agent: Address; name: string | null; purpose?: string; stewardship?: DelegationWire | null; membership?: DelegationWire | null },
): Promise<void> {
  try {
    const signHash = await signHashFor(via, person, auth);
    const self = toWire(await issueSiteDelegation(person, person, signHash, 12 * 3600));
    // A FAILED read is not an empty record (2026-10-15): writing `[entry]` over it would drop every other
    // organization this person stewards. No record (null) is empty; a throw skips the projection this time.
    let rec: { v?: number; relationships?: Record<string, unknown>[] } | null;
    try {
      rec = await vaultReadWithDelegation<{ v?: number; relationships?: Record<string, unknown>[] }>(self, 'impact-relationships');
    } catch (e) {
      console.warn('[org-create] impact-relationships not read — projection skipped rather than clobbered:', e);
      return;
    }
    const list = Array.isArray(rec?.relationships) ? rec!.relationships! : [];
    const key = org.agent.toLowerCase();
    const prev = list.find((r) => String(r.agent ?? '').toLowerCase() === key);
    const entry = {
      ...prev,
      agent: org.agent,
      agentName: org.name ?? (prev?.agentName as string | undefined) ?? null,
      kind: 'org',
      relation: 'steward',
      purpose: org.purpose ?? (prev?.purpose as string | undefined) ?? 'org',
      parent: person,
      createdAt: (prev?.createdAt as number | undefined) ?? Math.floor(Date.now() / 1000),
      grants: {
        ...(prev?.grants as Record<string, unknown> | undefined),
        ...(org.stewardship ? { stewardship: org.stewardship } : {}),
        ...(org.membership ? { membership: org.membership } : {}),
      },
      attestation: (prev?.attestation as Record<string, unknown> | undefined) ?? { type: 'gc:Attestation', confidence: 1, method: 'self-issued', basis: 'deployed and stewarded by the owner agent' },
    };
    const next = [...list.filter((r) => String(r.agent ?? '').toLowerCase() !== key), entry];
    await vaultWriteWithDelegation(self, 'impact-relationships', { v: 1, relationships: next });
  } catch (e) {
    console.warn('[org-create] impact-relationships vault projection failed:', e);
  }
}

/**
 * Set up an organization you'll help oversee — a home of its own, custodied by you, with a
 * private vault credential recording the link (ADR-0025) + a scoped grant for the app.
 * (Wraps createChildAgentForSite.)
 */
export async function createOrganization(
  home: Home,
  base: string,
  delegate: Address,
  via: Via = 'passkey',
  auth?: Auth,
  opts: {
    purpose?: string;
    requestedBy?: string;
    grantOrg?: Address;
    existingOrg?: Address;
    signAsOrg?: boolean;
    /** A NEW organization's type (lib/org-type.ts): written into its `org.profile` and returned on the payload so
     *  the related link carries it for Admin. Ignored on the existing-org path. */
    orgType?: OrgTypeV1;
    onProgress?: (p: { step: number; total: number; label: string; hint?: string }) => void;
    /** The organization is deployed and its vault bound — the point past which a retry must REUSE it rather
     *  than deploy another (src/lib/org-deploy-stash.ts). Not called on the existing-org path. */
    onDeployed?: (org: { orgAgent: Address; orgName: string }) => void;
  } = {},
): Promise<Result<{ org: Record<string, unknown>; grant: unknown }>> {
  // Normalize via: the session stores the display form ('Google'/'YouVersion' from the OAuth callback), but
  // isKmsVia/signHashFor/createChildAgentForSite match lowercase. Without this, a SOCIAL home's org-create
  // is misrouted to the passkey path (createChildAgentForSite → loadPasskey → empty pubkey → the account
  // factory reverts, "getAddressForAgentAccount reverted 0x1dacb0d2"). Lowercase makes isKmsVia true → the
  // Google/KMS org-create path.
  via = (String(via ?? '').toLowerCase() || 'passkey') as Via;
  // REUSE AN EXISTING ORG the person already stewards (select-existing GCO): skip the deploy + name claim
  // and mint the SAME grants org-create would (site → relying delegate, broker → grantOrg, stewardship →
  // person) as approved-hash (0x03) leaves, pre-approving all their digests in ONE `approveHash` userOp on
  // the already-deployed org. The org is custodied by the person, so `signHashFor(via, org, auth)` signs it —
  // one prompt, no deploy. `/oidc/grant` verifies the 0x03 site grant via ERC-1271 (approved-hash branch) and
  // writes the related-org link (credential/proofHash are optional there). Reuses the B4 approved-hash batch.
  if (opts.existingOrg) {
    const org = opts.existingOrg;
    // A member (or a steward whose current credential is not the org's on-chain owner)
    // connects as themselves with this org as context. Signing a UserOp as that org is
    // what produced AA24 on Field/Engage workspaces offered to Gather.
    if (opts.signAsOrg === false) {
      return {
        ok: true,
        org: {
          orgAgent: org,
          orgName: base,
          person: home.address,
          purpose: opts.purpose,
          requestedBy: opts.requestedBy,
        },
        grant: undefined,
      };
    }
    try {
      opts.onProgress?.({
        step: 1,
        total: 3,
        label: 'Connecting the organization…',
        hint: 'One approval — Gather27 never holds its keys.',
      });
      const signHash = await signHashFor(via, org, auth);
      const siteApp = buildApprovedSiteDelegation(org, delegate);        // org → relying app's delegate
      const stewardApp = buildApprovedSiteDelegation(org, home.address); // org → person (stewardship)
      const digests: Hex[] = [siteApp.digest, stewardApp.digest];
      // THE RE-MINT PATH for the Operational Intent grant. Every org that existed before that grant
      // shipped has none, and there is no other moment to issue one: it is minted by its delegator,
      // so only a ceremony the org's own custody signs can create it. Select-existing already
      // re-mints the site and stewardship grants for an org that is already deployed — this rides
      // the same approved-hash batch, so re-connecting an org is still one approval.
      const opSA = getClient(opts.requestedBy ?? '')?.operational_delegate as Address | undefined;
      let opGrant: ReturnType<typeof buildApprovedOperationalIntentDelegation> | undefined;
      if (opSA && opSA.toLowerCase() !== delegate.toLowerCase()) {
        opGrant = buildApprovedOperationalIntentDelegation(org, opSA);
        digests.push(opGrant.digest);
      }
      // THE RE-MINT PATH for the org→workspace READ grant too (whitelabel org_read_grant) — same
      // reasoning as the Operational Intent grant above: only a ceremony the org's own custody signs
      // can create it, and select-existing is where every pre-existing org picks it up.
      const orgReadCfg = getClient(opts.requestedBy ?? '')?.org_read_grant;
      let orgReadGrant: ReturnType<typeof buildApprovedOrgReadDelegation> | undefined;
      if (orgReadCfg && orgReadCfg.delegate.toLowerCase() !== delegate.toLowerCase()) {
        orgReadGrant = buildApprovedOrgReadDelegation(org, orgReadCfg.delegate as Address, orgReadCfg);
        digests.push(orgReadGrant.digest);
      }
      let brokerApp: ReturnType<typeof buildApprovedSiteDelegation> | undefined;
      if (opts.grantOrg && opts.grantOrg.toLowerCase() !== delegate.toLowerCase()) {
        brokerApp = buildApprovedSiteDelegation(org, opts.grantOrg);     // org → broker (Switchboard)
        digests.push(brokerApp.digest);
      }
      const approve = await approveGrantHashes(org, signHash, digests);
      if (!approve.ok) {
        const raw = approve.error;
        if (/AA24|signature error/i.test(raw)) {
          return {
            ok: false,
            error:
              'This organization isn’t signed by your current sign-in. Create a new host organization, or pick one you custody with this method.',
          };
        }
        return { ok: false, error: `grant approval failed: ${raw}` };
      }
      // The org already exists ⇒ its vault / channels / membership are already set up; nothing to seed.
      // uupg interop: still project the steward relationship (+ the fresh stewardship wire) into the
      // person's impact-relationships vault record — a select-existing may be this org's FIRST exposure
      // to a vault-reading relying app.
      opts.onProgress?.({ step: 2, total: 3, label: 'Recording the connection…' });
      await projectStewardRelationshipToVault(home.address, via, auth, { agent: org, name: base || null, purpose: opts.purpose, stewardship: toWire(stewardApp.delegation) });
      opts.onProgress?.({ step: 3, total: 3, label: 'Handing access to the app…' });
      return {
        ok: true,
        org: {
          orgAgent: org,
          orgName: base,
          person: home.address,
          purpose: opts.purpose,
          requestedBy: opts.requestedBy,
          brokerDelegation: brokerApp ? toWire(brokerApp.delegation) : null,
          stewardshipDelegation: toWire(stewardApp.delegation),
          operationalDelegation: opGrant ? toWire(opGrant.delegation) : undefined,
          readGrantDelegation: orgReadGrant ? toWire(orgReadGrant.delegation) : undefined,
        },
        grant: toWire(siteApp.delegation),
      };
    } catch (e) {
      return { ok: false, error: e instanceof Error ? e.message : 'existing-org grant failed' };
    }
  }
  // spec 256 — route by credential, like secureHome: a Google member's org is custodied by their
  // KMS C_sub and deployed server-side (ZERO device prompts); passkey/wallet sign on device.
  const say = opts.onProgress;
  say?.({
    step: 1,
    total: 5,
    label: 'Finding a name…',
    hint: 'This can take a moment — we’re setting the organization up.',
  });
  const r = isKmsVia(via)
    ? (auth?.token
        ? await createOrganizationWithGoogle(auth.token, base, delegate, opts, via, (s) =>
            say?.({ step: 2, total: 5, label: s, hint: 'This is the longer step — hang tight.' }),
          )
        : ({ ok: false, error: 'creating an org with an OIDC home needs a custody session' } as const))
    : await createChildAgentForSite(
        home.address,
        base,
        delegate,
        (s) => say?.({ step: 2, total: 5, label: s, hint: 'This is the longer step — hang tight.' }),
        undefined,
        { ...opts, sessionToken: auth?.token },
        via,
      );
  if (!r.ok) return r;
  const x = r.result;
  // spec 321 — enable channel storage AT CREATE (vault-key bind + standing delivery grant, signed as
  // the org): zero prompts on the KMS family; best-effort — the steward-gated Enable button on the
  // channels page remains the recovery path.
  say?.({ step: 3, total: 5, label: 'Opening its private records…', hint: 'The listing will live here — Gather27 only gets a read grant.' });
  // The vault bind is NOT best-effort (2026-10-15): without it the org has no key, every listing write fails
  // `vault_key_unauthorized`, and the only recovery is a steward-only button the host never sees. It used to be
  // caught below and the host told the organization was set up.
  const bound = await activateVaultIfNeeded(x.childAgent, via, auth);
  if (!bound.ok) return { ok: false, error: `the organization's private records could not be set up: ${bound.error}` };
  opts.onDeployed?.({ orgAgent: x.childAgent as Address, orgName: String(x.childName ?? base) });
  try {
    const bearer = homeBearerToken(auth);
    // The PERSON's side starts now, beside the organization's (GC, 2026-10-14: it ran after it, 3.5 s of a
    // first publish): the steward relationship in the person's own impact-relationships record reads nothing
    // the organization's setup writes, and the person's interactions plane is theirs, not the org's.
    // Best-effort as before — a failure is logged, never fatal.
    const projection = bearer
      ? projectStewardRelationshipToVault(home.address, via, auth, {
          agent: x.childAgent as Address,
          name: (x.childName as string | null) ?? null,
          purpose: opts.purpose,
          stewardship: (x.stewardshipDelegation as DelegationWire | null) ?? null,
          membership: (x.membershipDelegation as DelegationWire | null) ?? null,
        }).catch((e: unknown) => console.warn('[org-create] steward relationship projection failed:', e))
      : Promise.resolve();
    const ixp = bearer
      ? activateInteractionsIfNeeded(home.address, via, auth).then((r) => {
          if (!r.ok) console.warn('[org-create] creator interactions plane not enabled:', r.error);
        })
      : Promise.resolve();
    // The person's OWN records — the founder OrganizationMembership, then the steward relationship that cites its
    // ids — live on the person's interactions plane and name the organization only by address. They start as soon
    // as that plane is ready, beside the organization's vault setup below (GC, 2026-10-15: they ran after it, 3.7 s
    // of a Publish). Best-effort as before: a failure is logged, never fatal.
    const personRecords = bearer
      ? ixp
          .then(() =>
            writeOrganizationMembership({
              member: home.address,
              org: x.childAgent as Address,
              enrollmentSource: { kind: 'open-enrollment', enrollmentPolicyId: `org-create:${x.childAgent.toLowerCase()}` },
              memberAcceptanceRef: `org-create:${home.address.toLowerCase()}`,
              organizationDecisionRef: `org-create-decision:${x.childAgent.toLowerCase()}`,
              bearer,
            }),
          )
          .then((founderMembership) =>
            fetch(`/a2a/interactions/${home.address.toLowerCase()}/relationships.merge`, {
              method: 'POST',
              headers: { 'content-type': 'application/json' },
              body: JSON.stringify({
                session: bearer,
                entry: {
                  org: x.childAgent.toLowerCase(),
                  relationship: 'steward',
                  orgName: x.childName,
                  ...(x.stewardshipDelegation ? { delegations: [x.stewardshipDelegation] } : {}),
                  ...(founderMembership
                    ? {
                        membershipId: founderMembership.membershipId,
                        membershipSituationHash: founderMembership.membershipSituationHash,
                        enrollmentDecisionRef: founderMembership.enrollmentDecisionRef,
                      }
                    : {}),
                },
              }),
            }),
          )
          .catch((e) => console.warn('[org-create] steward membership/relationship write failed:', e))
      : Promise.resolve();
    // After the vault is bound, the rest is independent — run it together instead of a long queue.
    await Promise.all([
      activateInboxDeliveryIfNeeded(x.childAgent, via, auth).then((g) => {
        if (!g.ok) throw new Error(g.error);
      }),
      activateInteractionsIfNeeded(x.childAgent, via, auth, false, ORG_INTERACTIONS_SESSION_LEAF_TTL_SECONDS).then((ix) => {
        if (!ix.ok) console.warn('[org-create] interactions grant not provisioned:', ix.error);
      }),
      x.stewardshipDelegation
        ? vaultWriteWithDelegation(x.stewardshipDelegation, 'org.profile', { v: 1, displayName: x.childName, ...(opts.orgType ? { organizationType: opts.orgType } : {}) }).catch((e: unknown) =>
            console.warn('[org-create] org profile seed failed:', e),
          )
        : Promise.resolve(),
    ]);
    if (bearer) {
      say?.({ step: 4, total: 5, label: 'Recording that you oversee it…' });
      // The default "general" discussion channel is community messaging: a client that opted out of that
      // (whitelabel `provisioning.communityMessaging: false`) gets none. The channels page can still make one.
      const channel = provisionsCommunityMessaging(opts.requestedBy)
        ? fetch('/connect/channels', {
            method: 'POST',
            headers: { 'content-type': 'application/json', authorization: `Bearer ${bearer}` },
            body: JSON.stringify({ action: 'create', communityId: x.childAgent.toLowerCase(), title: 'general' }),
          }).catch((e) => console.warn('[org-create] default channel failed:', e))
        : Promise.resolve();
      await Promise.all([channel, personRecords, projection]);
    }
  } catch (e) {
    console.warn('[org-create] channel storage not auto-enabled (use Enable on the channels page):', e);
  }
  if (!homeBearerToken(auth)) {
    await projectStewardRelationshipToVault(home.address, via, auth, {
      agent: x.childAgent as Address,
      name: (x.childName as string | null) ?? null,
      purpose: opts.purpose,
      stewardship: (x.stewardshipDelegation as DelegationWire | null) ?? null,
      membership: (x.membershipDelegation as DelegationWire | null) ?? null,
    });
  }
  // The org's public naming write ran beside the setup above (connect-client createOrganizationWithGoogle); it
  // must land before this tab leaves for the relying app.
  await x.pendingWrites;
  say?.({ step: 5, total: 5, label: 'Handing access to the app…' });
  // ADR-0025: the `org` payload carries the private credential + the person SA so the
  // server's /oidc/grant step can write the vault; the relying app receives only the org
  // metadata + proofHash + (optional) brokerDelegation back via /token.
  return {
    ok: true,
    org: {
      orgAgent: x.childAgent,
      orgName: x.childName,
      person: x.person,
      purpose: x.purpose,
      requestedBy: x.requestedBy,
      proofHash: x.proofHash,
      credential: x.credential,
      brokerDelegation: x.brokerDelegation ?? null,
      membershipDelegation: x.membershipDelegation,   // person→org (org reads member)
      stewardshipDelegation: x.stewardshipDelegation,  // org→person (person reads org)
      operationalDelegation: x.operationalDelegation,  // org→app service agent (submit intents)
      readGrantDelegation: x.readGrantDelegation,      // org→app workspace (read one record family)
      ...(opts.orgType ? { orgType: opts.orgType } : {}), // the type the person chose (org.profile has the record)
    },
    grant: x.delegation,
  };
}

/**
 * A WORKSPACE AND THE ORGANIZATION THAT GOVERNS IT — the `workspace-create` ceremony since 2026-10-02 (the owner's
 * rule; `org.ttl` §2, `core.ttl`; `lib/workspace-governor.ts`).
 *
 * A `<label>.workspace` agent is a SERVICE that coordinates a workspace. It is not an organization and cannot have
 * members, so a workspace chartered on its own — which is what this ceremony did until today — was a roster with
 * nothing to belong to: the clubs and field workspaces wrote `org.membership:member:<sa>` records on a service agent.
 * Now the ceremony charters TWO agents from the one name the app asked for, in this order:
 *
 *   1. the GOVERNING ORGANIZATION, `<label>.org`, by exactly the road `org-create` takes (`createOrganization`): its
 *      vault, its planes, the founder's own OrganizationMembership, the steward relationship, the app's site grant;
 *      then its link in the person's tree — org-create writes that link at `/oidc/grant` from the token's `org`
 *      payload, and here that payload is the workspace's, so the organization's is written directly;
 *   2. the WORKSPACE agent, `<label>.workspace`, with the organization as the PARENT on its link (`ap:charteredUnder`
 *      — "whose it is") and the PERSON as its steward (`steward`: the custodian keeps acting for it, because an
 *      organization has no session and every steward gate checks the wire against the person);
 *   3. the pair of records that make the governance readable from either side: `workspace:<ws>` in the
 *      organization's vault and `workspace.governor` in the workspace's.
 *
 * NO WORKSPACE WITHOUT A GOVERNOR. A failure at step 1 charters nothing else; a failure after the workspace is
 * deployed fails the ceremony and names both agents, the way a failed vault binding already does, rather than
 * returning a workspace every reader would treat as legacy. The token's `org` payload stays the workspace's —
 * `orgAgent` is still the workspace, every field an app reads today is unchanged — and gains the governor.
 */
export async function createGovernedWorkspace(
  home: Home,
  name: string,
  delegate: Address,
  via: Via,
  auth: Auth | undefined,
  opts: {
    purpose?: string;
    requestedBy?: string;
    grantOrg?: Address;
    onProgress?: (p: { step: number; total: number; label: string; hint?: string }) => void;
  } = {},
): Promise<Result<{ org: Record<string, unknown>; grant: unknown }>> {
  via = (String(via ?? '').toLowerCase() || 'passkey') as Via;
  const token = homeBearerToken(auth);
  if (!token) return { ok: false, error: 'Your Home session is needed to create a workspace.' };
  const purpose = opts.purpose ?? 'field-workspace';
  const say = opts.onProgress;
  const total = 5;
  const step = (n: number, label: string, hint?: string) => say?.({ step: n, total, label, ...(hint ? { hint } : {}) });

  // 1. THE ORGANIZATION FIRST. Its progress is org-create's own, re-stepped under this ceremony's count.
  step(1, 'Creating the organization that will govern it…', 'This is the longer step — hang tight.');
  const org = await createOrganization(home, name, delegate, via, auth, {
    purpose,
    requestedBy: opts.requestedBy,
    grantOrg: opts.grantOrg,
    onProgress: (p) => step(1, p.label, p.hint),
  });
  if (!org.ok) return { ok: false, error: `the organization could not be created, so no workspace was: ${org.error}` };
  const governor = (org.org.orgAgent as Address | undefined)?.toLowerCase() as Address | undefined;
  const governorName = String(org.org.orgName ?? '');
  const orgStewardship = org.org.stewardshipDelegation as DelegationWire | undefined;
  if (!governor || !orgStewardship) return { ok: false, error: 'the organization was created without a stewardship wire, so no workspace was' };
  // Its link, in the person's tree — org-create leaves this to `/oidc/grant`, whose `org` payload here is the
  // workspace's. Written now rather than later because the workspace's own link hangs UNDER it, and the link
  // store refuses a parent the person does not already hold.
  step(2, 'Recording that you steward the organization…');
  const linked = await fetch('/connect/related-orgs', {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
    body: JSON.stringify({
      person: home.address,
      orgAgent: governor,
      orgName: governorName,
      purpose,
      requestedBy: opts.requestedBy ?? '',
      kind: 'org',
      parent: home.address,
      relationship: 'steward',
      siteDelegation: org.grant ?? null,
      stewardshipDelegation: orgStewardship,
      proofHash: (org.org.proofHash as string | undefined) ?? null,
    }),
  });
  invalidateRelatedOrgs();
  if (!linked.ok) {
    const e = (await linked.json().catch(() => ({}))) as { error?: string };
    return { ok: false, error: `${governorName || 'the organization'} was created but could not be linked to your home, so no workspace was: ${e.error ?? linked.status}` };
  }

  // 2. THE WORKSPACE, under the organization, stewarded by the person.
  const created = await createManagedAgent(
    { kind: 'workspace', label: name, parent: governor, steward: home.address, person: home.address, via },
    token,
    (s) => step(3, s),
  );
  if (!created.ok) return { ok: false, error: `${governorName} is ready, but its workspace could not be created: ${created.error}` };
  const ws = created.result.agent;
  const wsStewardship = created.result.stewardshipDelegation;
  // The realm is USABLE from the first approval or it is not created: the same storage trio org-create runs —
  // vault binding is REQUIRED (every ws-* write gates on it), delivery + interactions are best-effort like everywhere.
  step(4, 'Enabling workspace storage…');
  const bound = await activateVaultIfNeeded(ws, via, auth);
  if (!bound.ok) return { ok: false, error: bound.error };
  const delivery = await activateInboxDeliveryIfNeeded(ws, via, auth);
  if (!delivery.ok) console.warn('[workspace-create] delivery grant not provisioned:', delivery.error);
  const ix = await activateInteractionsIfNeeded(ws, via, auth, false, ORG_INTERACTIONS_SESSION_LEAF_TTL_SECONDS);
  if (!ix.ok) console.warn('[workspace-create] interactions grant not provisioned:', ix.error);

  // 3. THE PAIR. Required: a workspace without its pointer is a legacy one to every reader, which is the state this
  // ceremony exists to stop producing.
  step(5, 'Recording which organization governs it…');
  if (!wsStewardship) return { ok: false, error: `${created.result.name} was created without a stewardship wire, so its governor could not be recorded` };
  // Spec 424 — the member-read path: the workspace grants its governing ORG a CONTENT read of itself, signed as the
  // workspace (server-side for a KMS workspace). A member then reads the workspace's content by chaining their org
  // membership onto this grant (the field runtime presents the chain) — "read through the governor", never a
  // relationship to the workspace agent (the hub doctrine). Content only; best-effort, like the other ws grants.
  let governorRead: DelegationWire | undefined;
  try {
    const signWs = await signHashFor(via, ws, auth);
    governorRead = toWire(await issueOrgReadDelegation(ws, governor, { server: MCP_SERVER_ID, resources: WORKSPACE_CONTENT_SCOPE }, signWs));
  } catch (e) { console.warn('[workspace-create] governor content-read grant not minted:', e instanceof Error ? e.message : String(e)); }
  try {
    await writeGovernancePair({ orgStewardship, wsStewardship, governor, workspace: ws, label: created.result.name || name, purpose, ...(governorRead ? { governorRead } : {}) });
  } catch (e) {
    return { ok: false, error: `${created.result.name} and ${governorName} were created, but the record that ${governorName} governs the workspace could not be written: ${e instanceof Error ? e.message : String(e)}` };
  }
  // Spec 424 §2.3 — the serving-plane projection every MEMBER's `related-orgs` synthesizes into an enterable
  // workspace row (so a member finds the workspace and is handed the workspace→org content grant to chain onto).
  // Best-effort and rebuildable from the pair above; a member with no projection simply sees no workspace yet.
  if (governorRead) {
    await fetch('/connect/related-orgs', {
      method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
      body: JSON.stringify({ person: home.address, orgAgent: governor, governedWorkspace: { workspace: ws, workspaceName: created.result.name || name, grant: governorRead } }),
    }).catch((e) => console.warn('[workspace-create] governed-workspace projection not written:', e instanceof Error ? e.message : String(e)));
  }
  return {
    ok: true,
    org: {
      orgAgent: ws,
      orgName: created.result.name,
      kind: 'workspace',
      purpose,
      person: home.address,
      parent: governor,
      governor,
      governorName,
    },
    grant: wsStewardship,
  };
}

/**
 * `/oidc/grant` proves the PERSON authorized the app (ERC-1271 + unrevoked person→delegate).
 * Org-create used to POST the org's 0x03 site grant as that proof. A freshly deployed org
 * grant then failed closed as "delegation is revoked" (invite / Gather host onboard).
 * Create the org first, then mint the same person grant site-login uses; the org wire
 * rides in the payload.
 */
export async function personGrantForOrgCreate(
  home: Home,
  delegate: Address,
  via: Via,
  auth: Auth | undefined,
  created: { org: Record<string, unknown>; grant: unknown },
  sessionKey?: Address,
): Promise<Result<{ grant: unknown; org: Record<string, unknown>; sessionDelegation?: DelegationWire }>> {
  const permitted = await givePermission(home, delegate, via, auth, sessionKey);
  if (!permitted.ok) return permitted;
  return {
    ok: true,
    grant: permitted.grant,
    org: {
      ...created.org,
      siteDelegation: created.grant,
      stewardshipDelegation: created.org.stewardshipDelegation ?? created.grant,
    },
    sessionDelegation: permitted.sessionDelegation,
  };
}

/**
 * ③ — Give a missional-community app permission to act for you, on your terms (scoped,
 * revocable). The delegation is signed by YOUR custodian (passkey or the wallet EOA), so the
 * signer is chosen by `via`. Returns the signed grant to hand to the app.
 */
export async function givePermission(
  home: Home,
  delegate: Address,
  via: Via = 'passkey',
  auth?: Auth,
  /** spec 270 v4 W2 — the RELYING APP's session-key address (the relying app generates the keypair and
   *  keeps the private key; only its public address reaches the home). When present, the same credential
   *  that signs the site delegation also signs the DEL-001 leaf binding that key to the person SA. */
  sessionKeyAddress?: Address,
  /** spec 272/243 — when the relying app requested the `x402-pay` template, ALSO issue a capped
   *  payment delegation from the member's TREASURY SA (custodied by the SAME credential as the person
   *  SA, MAM-D2 — so the same `signHash` authorizes it; the custodian never appears as a party). The
   *  public delegation crosses back to the app, which stores it in the payee's vault and redeems it per
   *  paid read. `mode`: 'push' (x402 — OPEN delegate, the reader redeems) | 'pull' (delegate = payee,
   *  the provider redeems on its schedule — subscriptions). The PaymentEnforcer caps every charge. */
  payment?: {
    treasury: Address;
    payee: Address;
    asset: Address;
    maxAmountPerCharge: bigint;
    maxAggregate: bigint;
    maxRedemptionsPerWindow?: number;
    windowSeconds?: number;
    mode?: 'push' | 'pull';
    /** WHO MAY PRESENT the mandate, when that is not the payee — the app's own service agent (see
     *  `paymentConfig.redeemer` and `lib/new-member.ts#mandateDelegate`). Ignored on `push`, whose
     *  delegate is OPEN by construction; defaults to the payee on `pull`, which is what every
     *  ceremony minted before this field existed. */
    redeemer?: Address;
    /** spec 272 — also CHARGE the first/top-up payment in THIS ceremony (all-custodian via signHash):
     *  the person SA redeems the push delegation → `chargeAmount` USDC moves person-treasury → payee.
     *  The relying app verifies the returned settlementHash on-chain and mints a `reads`-read pass. */
    chargeNow?: boolean;
    chargeAmount?: bigint;
    edition?: string;
    /** spec 272 recurring lane — when set, this connect is a SUBSCRIPTION: in addition to the first
     *  period's push charge, mint a STANDING `treasury → payee` PULL mandate (delegate = payee) the
     *  provider can redeem once per `periodSeconds` to renew, capped at `chargeAmount`/period and
     *  `chargeAmount × periods` total. Returned as `pullDelegation`; the app stores it in the payee's
     *  vault. (Unattended redemption needs the provider's signer — left to an owner-online step.) */
    subscription?: { periodSeconds: number; periods?: number };
  },
  /** spec 345 — when the requesting client's whitelabel entry declares `self_vault_grant`, mint
   *  it in THIS SAME ceremony: delegator = delegate = home.address, no org, no relationship
   *  write. Lets a person publish under their own identity without becoming a fake "org". */
  selfVaultScope?: SelfVaultGrantConfig,
  /** Opt-in per client (registry standingGrant: with-self-vault). Absent means the rules below are
   *  exactly what they always were, so no other app's ceremony changes. */
  reuse?: { reuseWithSelfVault?: boolean },
): Promise<Result<{ grant: unknown; sessionDelegation?: DelegationWire; paymentDelegation?: DelegationWire; pullDelegation?: DelegationWire; settlementHash?: Hex; selfVaultGrant?: DelegationWire; reused?: boolean }>> {
  try {
    // REUSE the standing grant when this browser already minted one for (person, delegate) and the
    // ceremony carries nothing else (no session leaf, no payment, no self-vault grant): its digest
    // approval is already on-chain, so re-approving an identical-scope duplicate costs a whole
    // userOp for nothing. A self-vault grant request disqualifies the cache hit for the same reason
    // a session leaf or payment does — a cached site delegation predates the vault scope and would
    // silently return no selfVaultGrant on every repeat connect otherwise.
    // /oidc/grant re-verifies revocation + ERC-1271 per use; the caller clears the cache and mints
    // fresh if the reused grant is refused (one explicit fallback, ADR-0013).
    if (!sessionKeyAddress && !payment && !selfVaultScope) {
      const standing = loadStandingGrant(home.address, delegate);
      if (standing) return { ok: true, grant: standing, reused: true };
    }
    // The opted-in variant (registry `standingGrant: 'with-self-vault'`): a self-vault ceremony whose
    // two digests (site + self-vault) are fixed for the client, so the approval userOp would be a
    // byte-identical repeat. Keyed on the scope too, so a widened scope mints fresh. Same fallback
    // as above if /oidc/grant refuses the reuse. Absent the opt-in this branch never runs.
    if (!sessionKeyAddress && !payment && selfVaultScope && reuse?.reuseWithSelfVault) {
      const standing = loadStandingGrantWithSelfVault(home.address, delegate, selfVaultScope);
      if (standing) return { ok: true, grant: standing.wire, selfVaultGrant: standing.selfVaultGrant, reused: true };
    }
    const signHash = await signHashFor(via, home.address, auth);
    let delegation: Awaited<ReturnType<typeof issueSiteDelegation>>;
    let sessionDelegation: DelegationWire | undefined;
    let selfVaultDelegation: Awaited<ReturnType<typeof issueSiteDelegation>> | undefined;
    if (isKmsVia(via)) {
      // KMS custody (email / phone / Google — GC, 2026-10-22): the custodian SIGNS each grant, no transaction. The
      // approved-hash batch in the other branch exists to spare a passkey one prompt per grant; a KMS custodian has
      // no prompt, and its approval userOp was a 4–5 s chain wait on every sign-in and again on every org-create
      // return (the single-host timeline, 2026-10-21). /oidc/grant and the relying app verify a signed wire through
      // the same ERC-1271 call as a 0x03 one, and the sign-in self-grant (projectStewardRelationshipToVault) has
      // always been signed this way. Three signatures in parallel: one /sign round trip each.
      const [site, leaf, selfVault] = await Promise.all([
        issueSiteDelegation(home.address, delegate, signHash),
        sessionKeyAddress ? issueSessionDelegation(home.address, sessionKeyAddress, signHash, [delegate]) : Promise.resolve(undefined),
        selfVaultScope ? issueSelfVaultGrant(home.address, selfVaultScope, signHash) : Promise.resolve(undefined),
      ]);
      delegation = site;
      sessionDelegation = leaf ? toWire(leaf) : undefined;
      selfVaultDelegation = selfVault;
    } else {
      // B4 — batch the person-SA grants (site + the DEL-001 session leaf) via APPROVED-HASH: build both as
      // `0x03` leaves and pre-approve their digests in ONE userOp on the person SA (one credential prompt),
      // instead of a separate off-chain signature per leaf. Only the PUBLIC `0x03` leaves cross back to the
      // relying app; its session private key never leaves its origin. The verifier validates each leaf via the
      // person SA's ERC-1271 `0x03` branch (UniversalSignatureValidator → ApprovedHashRegistry) — identical to
      // the org-create outbound grants, and to a signed leaf for the binding checks. (spec 253 + 270 v4 W2.)
      const siteApp = buildApprovedSiteDelegation(home.address, delegate);
      // Spec 408 §2.1 — the relying app's session key presents the person's delegations to THAT app's SA only.
      const sessionApp = sessionKeyAddress ? buildApprovedSessionDelegation(home.address, sessionKeyAddress, [delegate]) : undefined;
      // spec 345 — the self-vault grant folds into the SAME batch: delegator = delegate = home.address,
      // never touching org/stewardship machinery. NEVER call projectStewardRelationshipToVault for this.
      const selfVaultApp = selfVaultScope ? buildApprovedSelfVaultGrant(home.address, selfVaultScope) : undefined;
      const approve = await approveGrantHashes(
        home.address,
        signHash,
        [siteApp.digest, sessionApp?.digest, selfVaultApp?.digest].filter((d): d is Hex => Boolean(d)),
      );
      if (!approve.ok) return { ok: false, error: `grant approval failed: ${approve.error}` };
      delegation = siteApp.delegation;
      sessionDelegation = sessionApp ? toWire(sessionApp.delegation) : undefined;
      selfVaultDelegation = selfVaultApp?.delegation;
    }
    // x402 payment delegation — issued from the TREASURY, signed by the same credential, in the same
    // ceremony. delegate = OPEN (push: reader redeems) or the payee (pull: provider redeems).
    const payDeleg = payment
      ? await issuePaymentDelegation(
          payment.treasury,
          // WHEN money moves and WHO may collect it are two questions; this line used to answer both
          // from `mode` alone, which left an app whose redeeming agent is not its payee unable to
          // state either truthfully. `mandateDelegate` is the one place that is decided now, and it
          // returns the identical delegate for every config that predates `redeemer`.
          mandateDelegate(payment) ?? OPEN_DELEGATION,
          payment.payee,
          signHash,
          {
            asset: payment.asset,
            maxAmountPerCharge: payment.maxAmountPerCharge,
            maxAggregate: payment.maxAggregate,
            maxRedemptionsPerWindow: payment.maxRedemptionsPerWindow,
            windowSeconds: payment.windowSeconds,
          },
        )
      : undefined;
    // ALL-CUSTODIAN CHARGE (spec 272): redeem the just-minted push delegation IN this ceremony — the
    // person SA executes it, signed by the SAME credential (signHash), gaslessly. Moves chargeAmount USDC
    // person-treasury → payee; the relying app verifies the tx + mints a pass. Non-fatal: if the charge
    // fails (treasury underfunded), the delegation is still returned so the app can settle later.
    let settlementHash: Hex | undefined;
    if (payDeleg && payment?.chargeNow && payment.chargeAmount && payment.mode !== 'pull') {
      const charged = await chargePayment(home.address, payDeleg, signHash, {
        payee: payment.payee, asset: payment.asset, amount: payment.chargeAmount, edition: payment.edition ?? 'lbsb',
      });
      if (charged.ok) settlementHash = charged.settlementHash;
    }
    // SUBSCRIPTION (spec 272 recurring): ALSO mint a standing PULL mandate (delegate = payee, so the
    // provider redeems) from the SAME treasury, signed by the SAME credential. Per-period cap = the tier
    // price (chargeAmount); window = the billing period; one redemption per window; aggregate bounds the
    // number of auto-renewals. The app stores it in the payee's vault. This is the "person delegates the
    // payee the ability to charge a subscription" half — distinct from the push delegation used above.
    let pullDeleg: Awaited<ReturnType<typeof issuePaymentDelegation>> | undefined;
    if (payment?.subscription && payment.chargeAmount) {
      const perPeriod = payment.chargeAmount;
      const periods = BigInt(Math.max(1, payment.subscription.periods ?? 12));
      const aggregate = perPeriod * periods;
      pullDeleg = await issuePaymentDelegation(payment.treasury, payment.payee, payment.payee, signHash, {
        asset: payment.asset,
        maxAmountPerCharge: perPeriod,
        maxAggregate: aggregate <= payment.maxAggregate ? aggregate : payment.maxAggregate,
        maxRedemptionsPerWindow: 1,
        windowSeconds: payment.subscription.periodSeconds,
      });
    }
    const wire = toWire(delegation);
    // The plain site-login grant is reusable next connect (skips the approval userOp). Ceremonies
    // carrying a session leaf, payment, or self-vault grant are per-connect by construction —
    // never cached (see the matching read-side condition above).
    if (!sessionKeyAddress && !payment && !selfVaultScope) {
      saveStandingGrant(home.address, delegate, wire, Date.now() + 365 * 86_400_000);
    }
    if (!sessionKeyAddress && !payment && selfVaultScope && reuse?.reuseWithSelfVault && selfVaultDelegation) {
      // Both grants carry 365-day validity; the cache's own 30-day margin (grant-cache.ts) applies on read.
      saveStandingGrantWithSelfVault(home.address, delegate, selfVaultScope, wire, toWire(selfVaultDelegation), Date.now() + 365 * 86_400_000);
    }
    return {
      ok: true,
      grant: wire,
      sessionDelegation,
      paymentDelegation: payDeleg ? toWire(payDeleg) : undefined,
      pullDelegation: pullDeleg ? toWire(pullDeleg) : undefined,
      settlementHash,
      selfVaultGrant: selfVaultDelegation ? toWire(selfVaultDelegation) : undefined,
    };
  } catch (e) {
    // Surface the REAL failure. Wallet providers (EIP-1193) and some libs throw plain objects/strings
    // that fail `instanceof Error`, which used to collapse into an unactionable 'could not grant
    // permission'. Serialize whatever was thrown, and keep the full object in the console.
    console.error('[givePermission] grant failed:', e);
    const msg =
      e instanceof Error ? e.message
      : typeof e === 'string' ? e
      : (e && typeof e === 'object' && 'message' in e && typeof (e as { message?: unknown }).message === 'string') ? (e as { message: string }).message
      : (() => { try { return `could not grant permission: ${JSON.stringify(e)}`; } catch { return 'could not grant permission'; } })();
    return { ok: false, error: msg };
  }
}

/**
 * spec 272 recurring — OWNER-online subscription collection. The owner (custodian of the collection
 * treasury, e.g. lbsb-treasury.impact) signs, with their own credential, the redemption of every DUE
 * subscriber's standing pull mandate — one ceremony bills them all. signHashFor signs for the TREASURY
 * (the redeemer/delegate), so the treasury's ERC-1271 validates the owner credential as its custodian.
 * No held key: if the connecting person doesn't custody the treasury, every redemption simply fails.
 */
export async function collectDueSubscriptions(
  treasury: Address,
  via: Via,
  auth: Auth | undefined,
  opts: { asset: Address; edition: string; a2aBase: string; idToken: string },
  onStep?: (s: string) => void,
): Promise<Result<{ attempted: number; collected: number; results: Array<{ subscriptionId?: number; subject?: string; ok: boolean; settlementHash?: Hex; error?: string }> }>> {
  try {
    const signHash = await signHashFor(via, treasury, auth);
    const res = await collectSubscriptions({ treasury, asset: opts.asset, edition: opts.edition, a2aBase: opts.a2aBase, idToken: opts.idToken, signHash, onStep });
    if (!res.ok) return { ok: false, error: res.error ?? 'collection failed' };
    return { ok: true, attempted: res.attempted, collected: res.collected, results: res.results };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : 'could not collect subscriptions' };
  }
}

/**
 * spec 266 delegated content trust — PER-CUSTODIAN: each signing identity (bsb.impact, lbsb.impact,
 * demo-validator.impact) is authorized only by WHOEVER CUSTODIES that SA. The connected custodian signs ONCE
 * a delegation binding their SA → its KMS key; the content service verifies the SA actually signed it
 * (ERC-1271) before storing. `opts.targetSigner` scopes the ceremony to the single identity the custodian
 * connected as, so each runs a clean "1 of 1" (you can only delegate authority you hold). NO held key.
 */
export async function authorizeContentSigningForOwner(
  via: Via,
  auth: Auth | undefined,
  opts: { a2aBase: string; idToken: string; targetSigner?: string },
  onStep?: (s: string) => void,
): Promise<Result<{ attempted: number; authorized: number; results: Array<{ issuerName: string; ok: boolean; error?: string }> }>> {
  try {
    const base = opts.a2aBase.replace(/\/$/, '');
    onStep?.('Reading signing identities + their HSM-backed KMS keys…');
    const keysRes = (await fetch(`${base}/admin/content-signer-keys`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ id_token: opts.idToken }),
    }).then((r) => r.json()).catch(() => ({ ok: false }))) as { ok?: boolean; signers?: Array<{ issuerName: string; issuerSa: Address; delegateKey: Address }>; error?: string };
    if (!keysRes.ok) return { ok: false, error: keysRes.error ?? 'could not read content-signer keys' };
    // Scope to the identity the custodian connected as — they can only authorize the SA they custody.
    const all = keysRes.signers ?? [];
    const signers = opts.targetSigner ? all.filter((s) => s.issuerName.toLowerCase() === opts.targetSigner!.toLowerCase()) : all;
    if (opts.targetSigner && signers.length === 0) return { ok: false, error: `signing identity ${opts.targetSigner} not provisioned a key yet` };
    const results: Array<{ issuerName: string; ok: boolean; error?: string }> = [];
    const oneYear = 365 * 24 * 60 * 60;
    for (let i = 0; i < signers.length; i++) {
      const s = signers[i]!;
      onStep?.(`Authorizing ${s.issuerName} (${i + 1}/${signers.length})…`);
      try {
        // Sign AS the issuer SA (the owner custodies it). The leaf binds issuerSa → its KMS key address.
        const signHash = await signHashFor(via, s.issuerSa, auth);
        // Spec 408 §2.1 — the signing key acts AS the issuer: it presents the issuer's own authority, to the issuer.
        const leaf = toWire(await issueSessionDelegation(s.issuerSa, s.delegateKey, signHash, [s.issuerSa], oneYear));
        const stored = (await fetch(`${base}/admin/store-content-signer`, {
          method: 'POST', headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ id_token: opts.idToken, issuerName: s.issuerName, issuerSa: s.issuerSa, delegateKey: s.delegateKey, delegationLeaf: leaf }),
        }).then((r) => r.json()).catch(() => ({ ok: false }))) as { ok?: boolean; error?: string };
        results.push({ issuerName: s.issuerName, ok: !!stored.ok, error: stored.ok ? undefined : (stored.error ?? 'store failed') });
      } catch (e) {
        results.push({ issuerName: s.issuerName, ok: false, error: e instanceof Error ? e.message : 'sign failed' });
      }
    }
    return { ok: true, attempted: signers.length, authorized: results.filter((r) => r.ok).length, results };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : 'could not authorize content signing' };
  }
}

/**
 * The SERVICE-AGENT WIRE ceremony (agent-rule `service-agent-signing.md`). The custodian of a named
 * agent authorizes a relying service's KMS key to sign AS that agent — without the service ever
 * custodying it.
 *
 * The service is ASKED what to name as delegate rather than told: `GET /admin/signer-address` reads
 * the address straight off its signing key. Naming the service's agent account instead is the
 * classic error, and it mints a wire that can never verify — recovery yields the KEY, always.
 */
export async function authorizeServiceAgentWire(
  via: Via,
  auth: Auth | undefined,
  opts: { a2aBase: string; idToken: string;
    /** The agent the service is to act AS, when the app names one (a card-room club's workspace): the service
     *  answers for that identity and the custodian signs as it. Absent, the service names its own identity. */
    identity?: Address },
  onStep?: (s: string) => void,
): Promise<Result<{ identity: Address; delegate: Address; skills: string[]; expiresAt: string | null }>> {
  try {
    const base = opts.a2aBase.replace(/\/$/, '');
    const authHeader = { authorization: `Bearer ${opts.idToken}` };
    onStep?.('Reading the service\u2019s signing key\u2026');
    const who = (await fetch(`${base}/admin/signer-address${opts.identity ? `?identity=${encodeURIComponent(opts.identity)}` : ''}`, { headers: authHeader })
      .then((r) => r.json())
      .catch(() => ({}))) as { identity?: Address; delegate?: Address; skill?: string; skills?: string[]; error?: string };
    // The service names the SET it needs. `skill` is the single-skill form kept working, because a
    // service that reports one is asking for exactly one.
    const skills = who.skills?.length ? who.skills : who.skill ? [who.skill] : [];
    if (!who.identity || !who.delegate || skills.length === 0) {
      return { ok: false, error: who.error ?? 'the service could not report its signing key' };
    }
    // The app named an identity and the service answered for a different one: refuse rather than sign a wire
    // for whatever came back — the custodian is approving THIS agent's delegate, not the service's choice.
    if (opts.identity && who.identity.toLowerCase() !== opts.identity.toLowerCase()) {
      return { ok: false, error: `the service answered for ${who.identity}, not the agent named (${opts.identity})` };
    }

    // Sign AS the identity — the custodian custodies it, which is the whole premise of the ceremony.
    onStep?.(`Authorizing ${who.delegate.slice(0, 10)}\u2026 to act as this agent\u2026`);
    const signHash = await signHashFor(via, who.identity, auth);
    const wire = toWire(await issueServiceAgentWireDelegation(who.identity, who.delegate, skills, signHash));

    onStep?.('Handing the authorization to the service\u2026');
    const stored = (await fetch(`${base}/admin/service-wire`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...authHeader },
      body: JSON.stringify({ wire }),
    }).then((r) => r.json()).catch(() => ({}))) as { ok?: boolean; expiresAt?: string | null; error?: string };
    if (!stored.ok) return { ok: false, error: stored.error ?? 'the service refused the authorization' };

    return { ok: true, identity: who.identity, delegate: who.delegate, skills, expiresAt: stored.expiresAt ?? null };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : 'could not authorize the service agent' };
  }
}

/**
 * ④ — Consent to a specific agreement. Sign a FIXED consent digest with YOUR credential
 * (passkey / wallet / Google KMS) so a relying app can prove ON CHAIN (ERC-1271) that you —
 * or an org you steward, given as `party` — agreed to this exact agreement. Unlike a delegation,
 * this is a one-shot signature over a digest the relying app supplies; nothing is granted, scoped,
 * or revocable. `party` is the SA the signature must validate under: your home address for a
 * personal agreement, or a stewarded org SA you custody (same credential). The contract recomputes
 * the digest and verifies this signature via the party SA's ERC-1271 (AttestationRegistry RW1-1).
 */
export async function signConsent(party: Address, digest: Hex, via: Via = 'passkey', auth?: Auth): Promise<Result<{ signature: Hex }>> {
  try {
    const signHash = await signHashFor(via, party, auth);
    const signature = await signHash(digest);
    return { ok: true, signature };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : 'could not sign consent' };
  }
}

/**
 * ⑤ — spec 278 P5 vault-key ceremony. Authorize demo-mcp to wield your per-person vault KEK:
 * build a `VaultKeyAuthorization` (person SA → demo-mcp, one non-subdelegable VAULT_KEY_USE
 * caveat), sign its EIP-712 digest with YOUR credential (passkey / wallet / Google KMS — same
 * `signHashFor` rail as `signConsent`), and POST the signed authorization to demo-mcp's
 * `/custody/vault-key/bind` (same-origin via the `/mcp-bind` proxy). On success the person's
 * vault flips from fail-closed to live. The KEK (`kmsKeyRef`) is provisioned out-of-band by the
 * operator (spec 276 ap-provision-gcp); the home never holds key material — only signs the grant.
 */
export async function bindVaultKey(
  owner: Address,
  params: VaultKeyCeremonyParams,
  via: Via = 'passkey',
  auth?: Auth,
): Promise<Result<{ kmsKeyRef: string }>> {
  try {
    const { delegation, digest, expiresAt } = buildVaultKeyAuthorization(owner, params);
    const signHash = await signHashFor(via, owner, auth);
    delegation.signature = await signHash(digest); // person SA signs the authorization (ERC-1271)
    const res = await fetch('/mcp-bind/custody/vault-key/bind', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        owner,
        vaultId: params.vaultId,
        kmsKeyRef: params.kmsKeyRef,
        allowedResources: params.allowedResources,
        classificationCeiling: params.classificationCeiling,
        ops: params.ops,
        expiresAt,
        authorization: toWire(delegation),
      }),
    });
    const data = (await res.json().catch(() => ({}))) as { ok?: boolean; reason?: string; error?: string };
    if (!res.ok || data.ok !== true) {
      return { ok: false, error: data.reason ?? data.error ?? `vault-key bind failed (HTTP ${res.status})` };
    }
    return { ok: true, kmsKeyRef: params.kmsKeyRef };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : 'vault-key bind failed' };
  }
}

/**
 * One-call vault activation: provision the owner's per-person KEK (idempotent), discover this
 * server's delegate + authorized scope, then `bindVaultKey`. This is the whole spec-278 ceremony
 * behind a single function so onboarding (and the standalone /vault-key page) can fold it in — the
 * person just signs. Everything except the signature is system-supplied. `via`/`auth` follow the
 * same credential rail as the rest of onboarding (passkey/wallet sign locally; Google signs via KMS
 * with the session token).
 */
export async function activateVault(
  owner: Address,
  via: Via = 'passkey',
  auth?: Auth,
): Promise<Result<{ kmsKeyRef: string }>> {
  try {
    const info = (await fetch('/mcp-bind/custody/vault-key/server-info').then((r) => r.json())) as {
      serverId?: string; serverKey?: string;
      defaultResources?: string[];
      classificationCeiling?: string;
      ops?: ('read' | 'write')[];
    };
    // Phase C / NEW-C3 — the KEK-provision route wields the admin credential to mint a per-owner GCP KEK, so
    // it requires an OWNER-CONTROL PROOF (ERC-1271 over a freshness-bound challenge) rather than trusting the
    // body-supplied `owner`. Sign the same challenge the server re-derives (provisionChallengeHash). For KMS
    // homes this is server-side (no extra prompt); passkey/wallet homes take one extra onboarding signature
    // (UX follow-up: batch with the vault-key authorization below once the flow allows).
    const issuedAt = Math.floor(Date.now() / 1000);
    const provChallenge = keccak256(toBytes(['demo-mcp:vault-key-provision:v1', owner.toLowerCase(), String(issuedAt)].join('\n')));
    const provProof = await (await signHashFor(via, owner, auth))(provChallenge);
    const prov = (await fetch('/mcp-bind/custody/vault-key/provision', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ owner, issuedAt, proof: provProof }),
    }).then((r) => r.json())) as { ok?: boolean; kmsKeyRef?: string; error_description?: string; detail?: string };
    if (!prov?.ok || !prov.kmsKeyRef) {
      return { ok: false, error: prov?.error_description ?? prov?.detail ?? 'could not provision vault key' };
    }
    const bound = await bindVaultKey(
      owner,
      {
        vaultId: info.serverId ?? MCP_SERVER_ID,
        kmsKeyRef: prov.kmsKeyRef,
        serverKey: (info.serverKey ?? '0x0000000000000000000000000000000000000001') as Address,
        allowedResources: info.defaultResources ?? ['person-pii', 'org-sensitive', 'profile', 'vault:*'],
        classificationCeiling: info.classificationCeiling ?? 'regulated.high',
        ops: info.ops ?? ['read', 'write'],
      },
      via,
      auth,
    );
    // spec 317 W2 — once the vault is bound, provision the standing inbox-delivery grant too. Best-effort,
    // idempotent, and INERT until DELIVERY_SERVICE_SA is provisioned (so no extra device prompt today).
    // UX follow-up when provisioned: BATCH this signature with the vault-key authorization above rather
    // than a second consecutive prompt (feedback_value_steps_not_signatures / minimal device prompts).
    if (bound.ok) void activateInboxDeliveryIfNeeded(owner, via, auth);
    return bound;
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : 'vault activation failed' };
  }
}

/** Does this owner already have a live vault-key binding at demo-mcp? */
export async function isVaultBound(owner: Address): Promise<boolean> {
  try {
    const r = (await fetch(`/mcp-bind/custody/vault-key/is-bound?owner=${owner}`).then((x) => x.json())) as { bound?: boolean };
    return r?.bound === true;
  } catch {
    return false;
  }
}

/**
 * Activate the vault ONLY if the owner isn't already bound — so returning/already-activated members
 * are never re-prompted (preserves the one-tap recognized-enroll flow). Best-effort by design:
 * enroll flows call this fire-and-forget so a vault hiccup never blocks connecting to a relying app.
 */
export async function activateVaultIfNeeded(
  owner: Address,
  via: Via = 'passkey',
  auth?: Auth,
): Promise<Result<{ kmsKeyRef?: string; skipped?: boolean }>> {
  // Skip ONLY when the owner has a live binding that covers the `vault:*` namespace. A STALE binding (one
  // created before the namespace default — its allowedResources lacks `vault:*`) would let the member's app
  // records 401 forever; we re-bind to upgrade it (one extra signature, one time). Fail-open to activate on
  // any read error so a transient hiccup never wrongly skips.
  let status: { bound?: boolean; allowedResources?: string[] } = {};
  try {
    status = (await fetch(`/mcp-bind/custody/vault-key/is-bound?owner=${owner}`).then((r) => r.json())) as typeof status;
  } catch {
    /* fall through to activate */
  }
  const coversNamespace = Array.isArray(status.allowedResources) && status.allowedResources.includes('vault:*');
  if (status.bound === true && coversNamespace) {
    // Already-bound members (incl. those who predate the inbox-delivery grant) still get it provisioned —
    // idempotent + inert until DELIVERY_SERVICE_SA exists.
    void activateInboxDeliveryIfNeeded(owner, via, auth);
    return { ok: true, skipped: true };
  }
  return activateVault(owner, via, auth);
}

/**
 * spec 317 §3.2 / W2 — mint + store the standing INBOX-DELIVERY delegation: the recipient authorizes the
 * Home's delivery-service SA to WRITE message bodies (`message.body:*`) into the recipient's vault, so
 * inbound deliveries land the body under the recipient's OWN authority (residency, W3). Signed ONCE by
 * the recipient's ROOT credential (same rail as the vault-key authorization); stored server-side keyed by
 * the recipient. Best-effort + idempotent like `activateVaultIfNeeded`:
 *   - `DELIVERY_SERVICE_SA` unset ⇒ skip (the delivery service isn't provisioned yet — INERT, deploy-safe).
 *   - already stored ⇒ skip (no re-prompt).
 * The scope is `ops:['write']` only (audit F1) — the delegate can create/update bodies and nothing else;
 * demo-mcp enforces it per-delegation (spec 317 §3.2), AND-ed with the vault-key binding.
 */
export async function activateInboxDeliveryIfNeeded(
  recipient: Address,
  via: Via = 'passkey',
  auth?: Auth,
  force = false,
): Promise<Result<{ skipped?: boolean }>> {
  if (!DELIVERY_SERVICE_SA) return { ok: true, skipped: true }; // not provisioned ⇒ inert (deploy-safe)
  // spec 323 W3.2 — the delivery wire is custodied ONLY in the recipient's InteractionsDO now; the
  // Home stores no wire. Skip when the DO already holds it (`status.deliveryGranted` — an open read).
  // `force` re-issues even when present: /status reports only PRESENCE, not scope-currency, so a grant
  // minted before a resource-scope change (e.g. the dm-body write scope) stays stale and causes
  // `record_scope_denied` on send. A forced re-issue upserts the wire with the CURRENT scope. Idempotent.
  if (!force) {
    try {
      const st = (await fetch(`/a2a/interactions/${recipient.toLowerCase()}/status`).then((r) => r.json())) as { deliveryGranted?: boolean };
      if (st?.deliveryGranted) return { ok: true, skipped: true };
    } catch {
      /* fall through to (re)issue — a read hiccup never blocks provisioning the grant */
    }
  }
  try {
    const signHash = await signHashFor(via, recipient, auth);
    const delegation = await issueInboxDeliveryDelegation(recipient, DELIVERY_SERVICE_SA, MCP_SERVER_ID, signHash);
    // Hand the write-only wire to the recipient's InteractionsDO (self-verifies ERC-1271 before
    // storing). This is the ONLY residency now — no KV store.
    const res = await fetch(`/a2a/interactions/${recipient.toLowerCase()}/grant.delivery.put`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ delegation: toWire(delegation) }),
    });
    const data = (await res.json().catch(() => ({}))) as { ok?: boolean; error?: string };
    if (!res.ok || data.ok !== true) return { ok: false, error: data.error ?? `delivery-grant store failed (HTTP ${res.status})` };
    return { ok: true };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : 'inbox-delivery activation failed' };
  }
}

/**
 * spec 322 W2.2 — provision the principal's INTERACTIONS grant (plane B): issue
 * `principal → INTERACTIONS_SERVICE_SA` (steward-signed, interaction-record scopes) and hand the
 * wire to the principal's InteractionsDO (/a2a/interactions/<sa>/grant — the operational wire lives
 * WITH its delegate service, spec 322 §2; the DO self-verifies before storing). Inert until the
 * service SA is provisioned; skips when the DO already holds a grant. The issuance LEDGER row
 * (hash/metadata in the principal's vault) lands at W3 with the residency wave.
 */
export async function activateInteractionsIfNeeded(
  principal: Address,
  via: Via = 'passkey',
  auth?: Auth,
  force = false,
  /** The session-leaf lifetime. Omit for the PERSON case (short, self-healed on login — the default). Pass
   *  ORG_INTERACTIONS_SESSION_LEAF_TTL_SECONDS when enabling/re-enabling an ORG, service or workspace, whose
   *  steward signs once and will not return to re-sign (org-leaf-decay, 2026-10-03). */
  leafTtlSeconds?: number,
): Promise<Result<{ skipped?: boolean }>> {
  if (!INTERACTIONS_SERVICE_SA) return { ok: true, skipped: true }; // not provisioned ⇒ inert (deploy-safe)
  // TTL TIER (org-leaf-decay, 2026-10-03). An explicit value wins. Otherwise: a PERSON's own leaf is SHORT
  // (the connected user re-signs it each login — correct hygiene, changes nothing); an ORG/service/workspace
  // leaf is LONG (its steward signs once and will not return). We tell them apart by whether this principal is
  // the connected user — a best-effort decode of the session token's subject (the TTL is not a security
  // boundary, so an unreadable token falls to the org-long side: harmless for a person, never under-provisions
  // an org). This keeps the ambiguous scoped-agent panels from clobbering an org's long leaf with a short one.
  const connectedPerson = ((): string | undefined => {
    try {
      const p = auth?.token?.split('.')[1];
      if (!p) return undefined;
      return (JSON.parse(atob(p.replace(/-/g, '+').replace(/_/g, '/'))) as { sub?: string }).sub?.match(/0x[0-9a-fA-F]{40}/)?.[0]?.toLowerCase();
    } catch { return undefined; }
  })();
  const leafTtl = leafTtlSeconds ?? (connectedPerson && connectedPerson === principal.toLowerCase()
    ? PERSON_INTERACTIONS_SESSION_LEAF_TTL_SECONDS
    : ORG_INTERACTIONS_SESSION_LEAF_TTL_SECONDS);
  if (!force) {
    try {
      const st = (await fetch(`/a2a/interactions/${principal.toLowerCase()}/status`).then((r) => r.json())) as { granted?: boolean; current?: boolean; leafLive?: boolean | null };
      // Stale grants re-issue (scope widened — spec 322 W3); so does an EXPIRED SESSION LEAF (spec 412 W5): the leaf is
      // 12 h by issue and nothing else re-issues it, and an agent signing under an expired leaf mints releases that
      // verify nowhere. `leafLive === false` is the DO saying so; null (no leaf, unreadable) is not a reason to prompt.
      if (st?.granted && st?.current !== false && st?.leafLive !== false) return { ok: true, skipped: true };
    } catch { /* status hiccup — fall through to (re)issue; the DO upsert is idempotent */ }
  }
  try {
    const signHash = await signHashFor(via, principal, auth);
    const delegation = await issueInteractionsDelegation(principal, INTERACTIONS_SERVICE_SA, MCP_SERVER_ID, signHash);
    // NEW-C1 — also sign a DEL-001 session leaf binding the DO's interactions-session KMS key to the
    // principal, so the DO CLIENT-MINTS bound vault tokens (no server-mint). Best-effort: if the a2a hasn't
    // configured the interactions-session key (404), the DO stays on the server-mint bridge — the grant still
    // lands, so activation is never blocked. (One extra principal signature at enable; KMS homes sign silently.)
    let sessionLeafWire: DelegationWire | undefined;
    let sessionLeavesWire: DelegationWire[] | undefined;
    try {
      const sk = (await fetch(`/a2a/agent/interactions-session-key`).then((r) => r.json()).catch(() => null)) as { ok?: boolean; address?: string } | null;
      if (sk?.ok && sk.address && /^0x[0-9a-fA-F]{40}$/.test(sk.address)) {
        // Spec 408 §2.1 — the DO's session key presents the person's grants to the two service agents only.
        const presentsTo = [INTERACTIONS_SERVICE_SA, ...(DELIVERY_SERVICE_SA ? [DELIVERY_SERVICE_SA] : [])];
        // Spec 423 §2.1 route A — a PERSON gets a single short leaf (re-signed each login); an ORG gets a LADDER of
        // leaves whose windows tile forward (rung i valid for (i+1)·TTL), so a live rung exists for rungs·TTL with
        // no steward present to re-sign. Here the steward signs them all at once (KMS/persona homes sign silently).
        const rungs = leafTtl === PERSON_INTERACTIONS_SESSION_LEAF_TTL_SECONDS ? 1 : ORG_INTERACTIONS_SESSION_LEAF_LADDER_RUNGS;
        if (rungs > 1) {
          const leaves: DelegationWire[] = [];
          for (let i = 0; i < rungs; i++) leaves.push(toWire(await issueSessionDelegation(principal, sk.address as Address, signHash, presentsTo, (i + 1) * leafTtl)));
          sessionLeavesWire = leaves;
        } else {
          sessionLeafWire = toWire(await issueSessionDelegation(principal, sk.address as Address, signHash, presentsTo, leafTtl));
        }
      }
    } catch { /* session-key fetch/sign hiccup — DO falls back to the server-mint bridge; grant still lands */ }
    await ensureCsrfToken();
    const res = await fetch(`/a2a/interactions/${principal.toLowerCase()}/grant`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'content-type': 'application/json', ...csrfHeaders() },
      body: JSON.stringify({ delegation: toWire(delegation), ...(sessionLeavesWire ? { sessionLeaves: sessionLeavesWire } : sessionLeafWire ? { sessionLeaf: sessionLeafWire } : {}) }),
    });
    const data = (await res.json().catch(() => ({}))) as { ok?: boolean; error?: string };
    if (!res.ok || data.ok !== true) return { ok: false, error: data.error ?? `interactions grant store failed (HTTP ${res.status})` };
    return { ok: true };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : 'interactions activation failed' };
  }
}
