// Relying-site delegation issuance (ADR-0019). The central auth (this origin), with the
// person's ROOT passkey, issues a caveated, redeemer-bound ERC-7710 delegation from the
// person SA to the relying site's DELEGATE smart account. The site is a delegate, never a
// custodian of the person SA. Signed off-chain (EIP-712 `hashDelegation`) by the ROOT
// passkey via the same WebAuthn path that signs UserOps; the SA's ERC-1271 validates it at
// redemption. No new contracts — DelegationManager + enforcers are deployed.
import { keccak256, toBytes } from 'viem';
import {
  type Delegation,
  type Caveat,
  type VaultRecordScopeGrant,
  buildCaveat,
  encodeTimestampTerms,
  encodeAllowedTargetsTerms,
  encodeAllowedMethodsTerms,
  encodeValueTerms,
  buildPaymentMandateCaveats,
  buildVaultKeyUseCaveat,
  buildVaultRecordScopeCaveat,
  hashDelegation,
  buildSessionDelegation,
  ROOT_AUTHORITY,
} from '@agenticprimitives/delegation';
import type { Address, Hex } from '@agenticprimitives/types';
import { interactionsGrantScopes } from '@agenticprimitives/fabric/interactions';
import { CHAIN_ID, CONTRACTS } from './chain';
import { INTERACTIONS_APP_SCOPES } from '@ap-home/shared';
import { DELIVERY_SERVICE_SA, INTERACTIONS_SERVICE_SA, MCP_SERVER_ID } from './inbox-delivery';

type SignHash = (hash: Hex) => Promise<Hex>;

/** Wire form of a Delegation (bigint salt → string) for transport over postMessage / URL. */
export interface DelegationWire {
  delegator: Address;
  delegate: Address;
  authority: Hex;
  caveats: Caveat[];
  salt: string;
  signature: Hex;
}
export const toWire = (d: Delegation): DelegationWire => ({ ...d, salt: d.salt.toString() });

/** Least-privilege caveats for a relying site: time-boxed, value 0, scoped to the on-chain
 *  targets a relying site needs to act on the person's behalf (naming + relationship). */
function siteCaveats(validUntil: number): Caveat[] {
  return [
    buildCaveat(CONTRACTS.timestampEnforcer, encodeTimestampTerms(0, validUntil)),
    buildCaveat(CONTRACTS.valueEnforcer, encodeValueTerms(0n)),
    buildCaveat(
      CONTRACTS.allowedTargetsEnforcer,
      encodeAllowedTargetsTerms([
        CONTRACTS.agentRelationship,
        CONTRACTS.agentNameRegistry,
        CONTRACTS.permissionlessSubregistry,
      ]),
    ),
  ];
}

/**
 * Spec 397 — THE `ask-as-me` TEMPLATE: a person's delegation to a Home MCP's own key, pinned to `harness.ask`
 * and nothing else, time-boxed. It is the SAME shape as an agent's session wire (spec 372 S3c), with the person as
 * delegator: presented as `A2A-Session` at the person's agent it says "put this question to my agent as me" —
 * and nothing more. No value, no targets, no digest binding: an ask is not an intent, and every act the ask
 * reaches still parks for the person's own signature. Revocable on chain like every delegation of theirs.
 */
export function askAsMeCaveats(validUntil: number): Caveat[] {
  return [
    buildCaveat(CONTRACTS.timestampEnforcer, encodeTimestampTerms(0, validUntil)),
    buildCaveat(CONTRACTS.allowedMethodsEnforcer, encodeAllowedMethodsTerms([a2aSkillSelector('harness.ask')])),
  ];
}

/** Issue `person → the Home MCP's key`, ask-as-me caveats, signed by the person's custodian (`signHash`). */
export async function issueAskAsMeDelegation(
  personAgent: Address,
  delegateKey: Address,
  signHash: SignHash,
  validitySeconds = 60 * 60 * 24 * 30,
): Promise<Delegation> {
  const validUntil = Math.floor(Date.now() / 1000) + validitySeconds;
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  let salt = 0n;
  for (const b of bytes) salt = (salt << 8n) | BigInt(b);
  const d: Delegation = { delegator: personAgent, delegate: delegateKey, authority: ROOT_AUTHORITY, caveats: askAsMeCaveats(validUntil), salt, signature: '0x' };
  d.signature = await signHash(hashDelegation(d, CHAIN_ID, CONTRACTS.delegationManager));
  return d;
}

/** spec 253 — the approved-hash sentinel signature. A delegation carrying this 1-byte wire
 *  signature is NOT signed off-chain; instead its delegator SA pre-approved the EIP-712 digest
 *  in the ApprovedHashRegistry (inside the delegator's own userOp), and the SA's ERC-1271
 *  `isValidSignature` honors it via the `0x03` branch. Lets an org batch all of its outbound
 *  grants' approvals into one deploy userOp — one passkey instead of one-per-grant. */
export const APPROVED_HASH_SENTINEL: Hex = '0x03';

/** Build the unsigned delegation struct (shared by the signed + approved-hash variants). */
function buildSiteDelegation(delegator: Address, delegateSA: Address, validitySeconds: number): Delegation {
  const validUntil = Math.floor(Date.now() / 1000) + validitySeconds;
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  let salt = 0n;
  for (const b of bytes) salt = (salt << 8n) | BigInt(b);
  return {
    delegator,
    delegate: delegateSA,
    authority: ROOT_AUTHORITY,
    caveats: siteCaveats(validUntil),
    salt,
    signature: '0x',
  };
}

/** Issue `personAgent → delegateSA` with the default site caveats, signed by the ROOT
 *  credential (`signHash`). `delegate` is the relying site's delegate SA so redemption is
 *  bound to that account (DelegationManager requires `delegate == msg.sender`). */
export async function issueSiteDelegation(
  personAgent: Address,
  delegateSA: Address,
  signHash: SignHash,
  validitySeconds = 60 * 60 * 24 * 365,
): Promise<Delegation> {
  const d = buildSiteDelegation(personAgent, delegateSA, validitySeconds);
  const digest = hashDelegation(d, CHAIN_ID, CONTRACTS.delegationManager);
  d.signature = await signHash(digest); // ROOT passkey signs the EIP-712 delegation digest
  return d;
}

/** Issue `delegator → delegateSA` with CALLER-SUPPLIED caveats, signed by `signHash` (spec 283/284
 *  connect-treasury AUTHORIZE step — a scoped, monotonic host grant). Unlike issueSiteDelegation the
 *  caveats are explicit (e.g. lowered from a TreasuryAuthorityScope via connect-treasury.scopeToHostCaveats). */
export async function issueScopedDelegation(
  delegator: Address,
  delegateSA: Address,
  caveats: Caveat[],
  signHash: SignHash,
): Promise<Delegation> {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  let salt = 0n;
  for (const b of bytes) salt = (salt << 8n) | BigInt(b);
  const d: Delegation = { delegator, delegate: delegateSA, authority: ROOT_AUTHORITY, caveats, salt, signature: '0x' };
  const digest = hashDelegation(d, CHAIN_ID, CONTRACTS.delegationManager);
  d.signature = await signHash(digest);
  return d;
}

/** Issue `delegator -> delegateSA` authority over explicit vault record scopes.
 *
 * This is the generic substrate for vault-subject role ceremonies: the role row explains why the grant
 * exists; this delegation is the executable authority a resource server verifies.
 */
export async function issueVaultRecordScopeDelegation(
  delegator: Address,
  delegateSA: Address,
  grants: readonly VaultRecordScopeGrant[],
  signHash: SignHash,
  validitySeconds = 60 * 60 * 24 * 365,
): Promise<Delegation> {
  const validUntil = Math.floor(Date.now() / 1000) + validitySeconds;
  return issueScopedDelegation(
    delegator,
    delegateSA,
    [
      buildCaveat(CONTRACTS.timestampEnforcer, encodeTimestampTerms(0, validUntil)),
      buildCaveat(CONTRACTS.valueEnforcer, encodeValueTerms(0n)),
      buildVaultRecordScopeCaveat([...grants]),
    ],
    signHash,
  );
}

/** spec 253 — build a `delegator → delegateSA` site delegation WITHOUT an off-chain signature.
 *  Returns the delegation (wire signature = the `0x03` sentinel) plus its EIP-712 `digest`, so
 *  the caller batches `approvedHashRegistry.approveHash(digest)` into the DELEGATOR's own userOp.
 *  The digest excludes the signature field, so it is identical to what the relayer + on-chain
 *  redeem recompute. The delegator MUST be the account whose userOp runs the `approveHash`
 *  (i.e. the org being deployed) — only the org can approve hashes under its own address. */
export function buildApprovedSiteDelegation(
  delegator: Address,
  delegateSA: Address,
  validitySeconds = 60 * 60 * 24 * 365,
): { delegation: Delegation; digest: Hex } {
  const d = buildSiteDelegation(delegator, delegateSA, validitySeconds);
  const digest = hashDelegation(d, CHAIN_ID, CONTRACTS.delegationManager);
  d.signature = APPROVED_HASH_SENTINEL; // validated via the SA's approved-hash ERC-1271 branch
  return { delegation: d, digest };
}

// ─── spec 278 P5 — vault-key authorization (person SA → demo-mcp) ──────────────────────────────

export interface VaultKeyCeremonyParams {
  vaultId: string;
  /** The person's KEK resource name (provisioned by the operator via spec 276 ap-provision-gcp). */
  kmsKeyRef: string;
  /** demo-mcp's authorized delegate key (the binding's allowedServerId surface). */
  serverKey: Address;
  allowedResources: string[];
  classificationCeiling: string;
  ops: ('read' | 'write')[];
  validitySeconds?: number;
}

/** Build the unsigned `VaultKeyAuthorization` (person SA → demo-mcp, one non-subdelegable
 *  VAULT_KEY_USE caveat) + its EIP-712 digest + the binding `expiresAt`. The person's ROOT
 *  credential signs `digest`; the signed delegation is POSTed to /custody/vault-key/bind
 *  (spec 278 §3.3). Mirrors `issueSiteDelegation`'s build → hash → sign shape. */
export function buildVaultKeyAuthorization(
  owner: Address,
  p: VaultKeyCeremonyParams,
): { delegation: Delegation; digest: Hex; expiresAt: string } {
  const validUntil = Math.floor(Date.now() / 1000) + (p.validitySeconds ?? 60 * 60 * 24 * 90);
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  let salt = 0n;
  for (const b of bytes) salt = (salt << 8n) | BigInt(b);
  const caveat = buildVaultKeyUseCaveat({
    vaultId: p.vaultId,
    kmsKeyRef: p.kmsKeyRef,
    resources: p.allowedResources,
    classificationCeiling: p.classificationCeiling,
    ops: p.ops,
    noSubdelegation: true,
  });
  const d: Delegation = {
    delegator: owner,
    delegate: p.serverKey,
    authority: ROOT_AUTHORITY,
    caveats: [caveat],
    salt,
    signature: '0x',
  };
  const digest = hashDelegation(d, CHAIN_ID, CONTRACTS.delegationManager);
  return { delegation: d, digest, expiresAt: new Date(validUntil * 1000).toISOString() };
}

// ─── spec 317 W2a — the standing inbox-delivery delegation (record-scoped) ────────────────────

/** The vault resource scope an inbox-delivery delegate may write: message bodies ONLY. Mirrors
 *  demo-mcp's `resource = vault:<recordType>` (VAULT_RECORD_PREFIX) over fabric's `message.body:<id>`
 *  record type (`@agenticprimitives/fabric` `MESSAGE_BODY_RECORD_TYPE`) — kept as a local literal so
 *  this transport-agnostic module takes no fabric dependency. demo-mcp enforces the match (spec 317
 *  §3.2), intersected deny-by-default with the recipient's vault-key binding. */
export const INBOX_DELIVERY_RESOURCE_SCOPE = 'vault:message.body:*' as const;

/** The vault record that holds the owner's inbox document itself (`InboxDataV1` — envelopes + events +
 *  cases). spec 316 §11a cutover: the inbox is now vault-resident (not the Home's KV), so the standing
 *  inbox-delivery grant must also authorize read+write of THIS record — the a2a `messaging.deliver` skill
 *  appends to it (delivery) and the owner's Home reads/mutates it (render, archive, send). One record, one
 *  grant. demo-mcp record-scope-gates it exactly as it does the body records. */
export const INBOX_DATA_RESOURCE_SCOPE = 'vault:inbox.data' as const;


/** The vault record family that holds an ORG's invite tracking (`org.invite:<token>` — invitee email
 *  hash + status). Blast-zone (spec 315): invitee PII lives ENCRYPTED in the org vault, not KV; KV holds
 *  only a random-token→public-org pointer. Read+write over the org's steward-signed grant. */
export const ORG_INVITE_RESOURCE_SCOPE = 'vault:org.invite:*' as const;

/**
 * spec 317 §3.2 — issue the standing inbox-delivery delegation `recipient → deliveryServiceSA`,
 * signed once at onboarding by the recipient's ROOT credential (`signHash`). A `VAULT_RECORD_SCOPE`
 * caveat scopes the delegate to `INBOX_DELIVERY_RESOURCE_SCOPE` with op `write` ONLY — NO read, NO
 * list, NO delete (tombstone), per the security audit (F1): the delivery service can create/update
 * inbound message bodies and NOTHING else. demo-mcp decodes + enforces it (deny-by-default) AND-ed with
 * the recipient's vault-key binding, so it can act as the recipient for message bodies and nothing else
 * (least-privilege, ADR-0025). The delegate is a
 * DISTINCT delivery-service SA (never the vault-key `serverKey`), so its authority IS exactly this
 * grant. Stored server-side; the delivery service presents it at delivery to mint a `sub = recipient`
 * token (client-mint, delegate-signed — never `DEMO_ALLOW_SERVER_MINT`). Web3 is the authority
 * (ADR-0041); revoking this delegation stops inbound body writes at the substrate, fail-closed.
 *
 * `mcpServerId` is the demo-mcp server identifier the `DataScopeGrant.server` field binds (the scope
 * applies at that resource server); demo-mcp matches its own id before honoring the grant.
 */
/** Build the unsigned inbox-delivery delegation struct + its digest (shared by the signed and the
 *  approved-hash variants so their caveats/scope can never drift). Salt is randomized ONCE here, so the
 *  returned struct is the exact one to put on the wire (the digest must match what the DO recomputes). */
function buildInboxDeliveryStruct(
  recipient: Address,
  deliveryServiceSA: Address,
  mcpServerId: string,
  validitySeconds: number,
): { delegation: Delegation; digest: Hex } {
  const validUntil = Math.floor(Date.now() / 1000) + validitySeconds;
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  let salt = 0n;
  for (const b of bytes) salt = (salt << 8n) | BigInt(b);
  const caveats: Caveat[] = [
    // TESTNET POSTURE (spec 317 §5.1): read+write. The audit's write-only ideal (F1) requires a SEPARATE
    // owner read-delegation for `readInboxView` (the owner reading their OWN bodies); until that is provisioned,
    // spec 322 W3f — the delivery plane is WRITE-ONLY on the mail records: it can append a body and
    // the a2a skill can hand the envelope to the recipient's InteractionsDO, but it can NO LONGER
    // read anyone's inbox or dm bodies (closes the "delivery service reads your mail" testnet hole).
    // Reads ride the interactions grant through the DO. Invite tracking keeps read+write (the org's
    // steward surfaces look invites up by record).
    buildVaultRecordScopeCaveat([
      { server: mcpServerId, resources: [DM_BODIES_RESOURCE_SCOPE, INBOX_DATA_RESOURCE_SCOPE], ops: ['write'] },
      { server: mcpServerId, resources: [ORG_INVITE_RESOURCE_SCOPE], ops: ['read', 'write'] },
      // ADR-0055 — the org's Content Artifacts, read+write via the DO-held wire (steward-bridged content.* ops).
      { server: mcpServerId, resources: [CONTENT_RECORDS_RESOURCE_SCOPE], ops: ['read', 'write'] },
    ]),
    buildCaveat(CONTRACTS.timestampEnforcer, encodeTimestampTerms(0, validUntil)),
    buildCaveat(CONTRACTS.valueEnforcer, encodeValueTerms(0n)),
  ];
  const delegation: Delegation = { delegator: recipient, delegate: deliveryServiceSA, authority: ROOT_AUTHORITY, caveats, salt, signature: '0x' };
  const digest = hashDelegation(delegation, CHAIN_ID, CONTRACTS.delegationManager);
  return { delegation, digest };
}

export async function issueInboxDeliveryDelegation(
  recipient: Address,
  deliveryServiceSA: Address,
  mcpServerId: string,
  signHash: SignHash,
  validitySeconds = 60 * 60 * 24 * 365,
): Promise<Delegation> {
  const { delegation, digest } = buildInboxDeliveryStruct(recipient, deliveryServiceSA, mcpServerId, validitySeconds);
  delegation.signature = await signHash(digest); // recipient's ROOT credential authorizes the delivery service
  return delegation;
}

/** The OPERATOR DIRECTORY grant (2026-10-23; gc-estate/docs/operator-workspace.md): the operator org lets the
 *  directory service (the same DO-held delegate as inbox delivery) read and write exactly its directory records —
 *  contacts, the audit log, export requests — and nothing else. Held only by the operator org's InteractionsDO, which
 *  refuses any other scope (`directoryScopeExact`). Signed as the org by someone who custodies it. */
export const OPERATOR_DIRECTORY_SCOPE = ['vault:contact:*', 'vault:directory.audit:*', 'vault:export:*'] as const;
export async function issueOperatorDirectoryDelegation(
  operatorOrg: Address,
  directoryServiceSA: Address,
  mcpServerId: string,
  signHash: SignHash,
  // 30 days (security review 2026-10-23, #2): the grant reads the whole directory, so a copied one must go stale soon.
  // When it lapses the directory reads as "not enabled" and Admin offers Enable again.
  validitySeconds = 60 * 60 * 24 * 30,
): Promise<Delegation> {
  const validUntil = Math.floor(Date.now() / 1000) + validitySeconds;
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  let salt = 0n;
  for (const b of bytes) salt = (salt << 8n) | BigInt(b);
  const caveats: Caveat[] = [
    buildVaultRecordScopeCaveat([{ server: mcpServerId, resources: [...OPERATOR_DIRECTORY_SCOPE], ops: ['read', 'write'] }]),
    buildCaveat(CONTRACTS.timestampEnforcer, encodeTimestampTerms(0, validUntil)),
    buildCaveat(CONTRACTS.valueEnforcer, encodeValueTerms(0n)),
  ];
  const delegation: Delegation = { delegator: operatorOrg, delegate: directoryServiceSA, authority: ROOT_AUTHORITY, caveats, salt, signature: '0x' };
  delegation.signature = await signHash(hashDelegation(delegation, CHAIN_ID, CONTRACTS.delegationManager));
  return delegation;
}

/** spec 253 batching — the inbox-delivery grant WITHOUT an off-chain signature: the recipient (person SA
 *  being deployed) pre-approves this digest via `approveHash(digest)` batched into its own deploy userOp,
 *  so the wire validates through the SA's `0x03` approved-hash ERC-1271 branch — no per-grant passkey. */
export function buildApprovedInboxDeliveryDelegation(
  recipient: Address,
  deliveryServiceSA: Address,
  mcpServerId: string,
  validitySeconds = 60 * 60 * 24 * 365,
): { delegation: Delegation; digest: Hex } {
  const { delegation, digest } = buildInboxDeliveryStruct(recipient, deliveryServiceSA, mcpServerId, validitySeconds);
  delegation.signature = APPROVED_HASH_SENTINEL; // validated via the SA's approved-hash ERC-1271 branch
  return { delegation, digest };
}

/** The vault record holding a member's SHAREABLE profile card — what an org they joined may read
 *  (spec 321): display info the member chose to share, never the whole vault. */
export const MEMBER_PROFILE_RESOURCE_SCOPE = 'vault:member.profile' as const;

/** The membership directory record (spec 322 W2/W3 — the DO-managed vault residency). */
export const DIRECTORY_DATA_RESOURCE_SCOPE = 'vault:directory.data' as const;
/** Conversation/topic split (spec 324 §10 — renamed from board.* in the W6 key migration): the org's
 *  conversation descriptor index + per-topic docs + topic-namespace bodies. */
/** spec 338 §7 — a person's pending requests for a way to reach an unlisted agent, and the grants they
 *  hold. Issued in the interactions grant; NOT in the DO's staleness gate, so a grant signed before this
 *  feature keeps working for everything it already did (and cannot write these until it is re-issued). */
export const RESOLUTION_REQUESTS_RESOURCE_SCOPE = 'vault:resolution.requests' as const;
export const RESOLUTION_GRANTS_RESOURCE_SCOPE = 'vault:resolution.grants' as const;
export const CONVERSATION_INDEX_RESOURCE_SCOPE = 'vault:conversation.index' as const;
export const CONVERSATION_TOPIC_RESOURCE_SCOPE = 'vault:conversation.topic:*' as const;
export const TOPIC_BODIES_RESOURCE_SCOPE = 'vault:message.body:topic:*' as const;
/** 1-1 (DM) bodies — the DELIVERY plane's namespace; disjoint from channel bodies (FAB-SSO-2). */
export const DM_BODIES_RESOURCE_SCOPE = 'vault:message.body:dm:*' as const;
/** The person's AUTHORITATIVE org-relationship doc (spec 322 W3d) — Home `related:*` KV is a cache. */
export const RELATIONSHIPS_DATA_RESOURCE_SCOPE = 'vault:relationships.data' as const;
/** All per-org member profiles (`member.profile:<orgSA>`) — the person DO writes them per org. */
export const MEMBER_PROFILE_WILDCARD_SCOPE = 'vault:member.profile:*' as const;
/** spec 323 W2 — owner-own capability records reached self-only over the interactions grant: the
 *  person's community profile (V-1 remediation — delegation-authorized, replaces the bearer path),
 *  their private capability record (`vault:skills.data` — legacy key), and their home manifest master. */
export const IMPACT_PROFILE_RESOURCE_SCOPE = 'vault:impact-profile' as const;
/** The capability record's CURRENT key (ADR-0051). The Home writes here; `skills.data` below is the
 *  same record under its old name, kept so an unmigrated one still reads. Both are in the grant, or a
 *  save is refused at the vault-record-scope caveat with `record_scope_denied`. */
export const CAPABILITIES_DATA_RESOURCE_SCOPE = 'vault:capabilities.data' as const;
export const SKILLS_DATA_RESOURCE_SCOPE = 'vault:skills.data' as const;
export const HOME_MANIFEST_RESOURCE_SCOPE = 'vault:home.manifest' as const;
/** The person's portable control-plane timeline (spec 323 W2.3) — append via bridge, read self. */
export const CONTROL_EVENTS_RESOURCE_SCOPE = 'vault:control-events.data' as const;
/** Spec 363 W4 — the person's own note of WHO THEY LIVE WITH. Private tier by construction: not on
 *  chain, not derivable from it, and therefore never in the discovery KB (ADR-0040). Distinct from
 *  `vault:family:*`, which is the skills-app FAMILY-OFFICE namespace and a different subject entirely. */
export const HOUSEHOLD_RESOURCE_SCOPE = 'vault:household.data' as const;
/** Spec 370 P7 — the person's own conversation memory (what their agent resolved for them lately). Additive,
 *  like the household record: new grants carry it; an older grant is offered Enable. */
export const CONVERSATION_MEMORY_RESOURCE_SCOPE = 'vault:conversation.recent' as const;
/** Spec 381 — a run's provenance in the acting agent's vault (the task object's copy is the rebuild). */
export const RUN_PROVENANCE_RESOURCE_SCOPE = 'vault:run.provenance:*' as const;
/** Spec 391 — a step's raw result, offloaded to the agent's own vault when it is too large for the run's record. */
export const RUN_ARTIFACT_RESOURCE_SCOPE = 'vault:run.artifact:*' as const;
/** Spec 410 §4.4 — the citation beside a run's bundle: which chain-qualified registry anchored it, and in which estate. */
export const RUN_ANCHOR_RESOURCE_SCOPE = 'vault:run.anchor:*' as const;
/** Spec 414 A2 — a run's measurements beside its provenance. Additive: a grant signed before it denies the record until re-issued. */
export const RUN_MEASURES_RESOURCE_SCOPE = 'vault:run.measures:*' as const;
/** Spec 385 — the person's own SCOPED CONFIRMATION MEMORY: which "David" they meant, per (word, capability,
 *  argument). Evidence the resolver cites, never a grant a verifier reads (ADR-0041). Additive like the
 *  household record: a grant signed before this scope existed denies the record until re-issued. */
export const CONFIRMATION_PREFERENCES_RESOURCE_SCOPE = 'vault:confirmation.preferences' as const;
/** Spec 394 — the person's own STANDING INSTRUCTIONS: a declared default per (room, capability, argument). Evidence the
 *  resolver cites, never a grant. Additive: a grant signed before this scope existed denies the record until re-issued. */
export const STANDING_INSTRUCTIONS_RESOURCE_SCOPE = 'vault:standing.instructions' as const;
/** Spec 402 W1 — what the person's agent REMEMBERS about them (`memory.facts`): their own facts, in their own words. Additive,
 *  like the instructions: a grant signed before this scope existed denies the record until re-issued. */
export const MEMORY_FACTS_RESOURCE_SCOPE = 'vault:memory.facts' as const;
/** What the playbook REMEMBERS about the subjects of one skill family (`playbook.memory:<family>`): counts a
 *  review folds in, advice reads back. Behaviour, never authority. Additive: a grant signed before this scope
 *  existed denies the record until re-issued, and the review says so in its reply. */
export const PLAYBOOK_MEMORY_RESOURCE_SCOPE = 'vault:playbook.memory:*' as const;
/** The person's CARD-ROOM STUDY RECORDS (`cardroom.hand|style|read|note`, and a coach service's own `cardroom.client`):
 *  their hands as their seat saw them, their style in their words, their reads on players, and the notes the coach
 *  service they named writes back under a study grant. Additive, like playbook memory. */
export const CARDROOM_RESOURCE_SCOPE = 'vault:cardroom.*' as const;
/** Content-fabric records (spec 335 / ADR-0055): the person's Content Artifacts / releases, keyed
 *  `vault:content.<type>.<id>` — one namespace, read+write via the interactions grant. */
export const CONTENT_RECORDS_RESOURCE_SCOPE = 'vault:content.*' as const;
/** spec 324 W3 — the authoritative OrganizationMembership records (`org.membership:<orgSA>`): the party's
 *  own membership Situation + credential per org, written self-only through the InteractionsDO. Membership is
 *  the source of truth (ADR-0048 #3) — distinct from the delegations/listings that project it. */
export const ORG_MEMBERSHIP_WILDCARD_SCOPE = 'vault:org.membership:*' as const;

/** spec 324 §7 Tier-2 — the org's pending MembershipApplications doc (`org.applications`), read by the steward
 *  + appended by applicants, both via the Home over the interactions grant. A plain org-vault doc (not inbox). */
export const ORG_APPLICATIONS_RESOURCE_SCOPE = 'vault:org.applications' as const;

/** spec 334 §3 — the coordination serving plane's vault docs (spec 332 §5 catalog): the intake doc,
 *  the endeavor index, and the per-endeavor event log + projected state (`coordination.endeavor:*`
 *  covers both `coordination.endeavor:<id>` and `coordination.endeavor:events:<id>`). ADDITIVE
 *  scopes, same precedent as org.applications: a grant lacking them is denied per-record at
 *  demo-mcp (endeavor.* ops surface "re-enable"), never blanket-staled. */
export const COORDINATION_REQUESTS_RESOURCE_SCOPE = 'vault:coordination.requests' as const;
export const COORDINATION_INDEX_RESOURCE_SCOPE = 'vault:coordination.index' as const;
export const COORDINATION_ENDEAVOR_WILDCARD_SCOPE = 'vault:coordination.endeavor:*' as const;
/** spec 354 §4.3 — the agent's compiled playbook (ArchetypeAssignmentV1). ADDITIVE, not in REQUIRED_SCOPES:
 *  a grant signed before archetypes existed keeps working for everything else and is denied ONLY this
 *  record until the steward re-enables — the honest "re-enable to set a playbook" signal, never a blanket
 *  stale. Behavior, not authority: the record moves no grant. */
export const ARCHETYPE_ASSIGNMENT_RESOURCE_SCOPE = 'vault:archetype.assignment' as const;

/** spec 360 — the PARTIES' receipt of a transfer, keyed by transaction (`payment.receipt:<tx>`). ADDITIVE,
 *  like the playbook scope above: an agent whose grant predates this simply has no receipts written, which
 *  is a visible gap rather than an estate-wide outage. Both sides hold a copy — the payer's is written by
 *  the payer's grant, the payee's by the payee's own, the way mail is admitted (nothing the sender
 *  presents carries write authority). */
export const PAYMENT_RECEIPT_RESOURCE_SCOPE = 'vault:payment.receipt:*' as const;

// The product's own namespaces on the interactions grant live in ONE module both apps import
// (`@ap-home/shared`, spec 399 §4): re-exported here for the callers that always read them from
// this file; the caveat below is built from the same list the runtime's genesis planes append.
export { APP_COORDINATION_READ_SCOPES, APP_OWN_NAMESPACE_READ_SCOPES, APP_OWN_NAMESPACE_SEED_SCOPES, INTERACTIONS_APP_SCOPES } from '@ap-home/shared';

/**
 * spec 322 §2 plane B — the INTERACTIONS grant `principal → INTERACTIONS_SERVICE_SA`, signed once
 * by the steward's credential AS the principal at the enable ceremony. Exercised only by the
 * principal's InteractionsDO (the serialized execution point); scoped to the interaction records
 * (board + bodies + inbox + directory), read+write. The wire lives WITH its delegate service (the
 * DO's storage) — never in app KV, never readable by member/app scopes (a stored wire is a bearer
 * secret under server-mint; spec 322 §2).
 */
function buildInteractionsStruct(
  principal: Address,
  interactionsServiceSA: Address,
  mcpServerId: string,
  validitySeconds: number,
): { delegation: Delegation; digest: Hex } {
  const validUntil = Math.floor(Date.now() / 1000) + validitySeconds;
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  let salt = 0n;
  for (const b of bytes) salt = (salt << 8n) | BigInt(b);
  const caveats: Caveat[] = [
    // THE CORE SCOPES COME FROM THE PACKAGE (`@agenticprimitives/fabric/interactions`): the one list this
    // Home and the agent runtime's genesis planes both compose from — a scope added on one side without the
    // other was the drift that made an enabled-looking org 409 on its first new-record write. What this app
    // APPENDS is its own namespaces (spec 334 §6): two shapes, both read-only/additive — the uupg app's
    // enumerated public-claim types, and any relying app's ontology namespace ROOT (e.g. vault:newcity:*) —
    // the platform never names a domain record; the org's playbook does. Then the same namespace read+write
    // for steward SEEDING of a sandbox org's vault (the agent never reaches this — its read path is a
    // different op, and the write op is steward-gated; see APP_OWN_NAMESPACE_SEED_SCOPES).
    buildVaultRecordScopeCaveat(interactionsGrantScopes(mcpServerId, INTERACTIONS_APP_SCOPES)),
    buildCaveat(CONTRACTS.timestampEnforcer, encodeTimestampTerms(0, validUntil)),
    buildCaveat(CONTRACTS.valueEnforcer, encodeValueTerms(0n)),
  ];
  const delegation: Delegation = { delegator: principal, delegate: interactionsServiceSA, authority: ROOT_AUTHORITY, caveats, salt, signature: '0x' };
  const digest = hashDelegation(delegation, CHAIN_ID, CONTRACTS.delegationManager);
  return { delegation, digest };
}

export async function issueInteractionsDelegation(
  principal: Address,
  interactionsServiceSA: Address,
  mcpServerId: string,
  signHash: SignHash,
  validitySeconds = 60 * 60 * 24 * 365,
): Promise<Delegation> {
  const { delegation, digest } = buildInteractionsStruct(principal, interactionsServiceSA, mcpServerId, validitySeconds);
  delegation.signature = await signHash(digest); // the steward's credential authorizes the execution point
  return delegation;
}

/** spec 253 batching — the interactions grant as an approved-hash (0x03) wire; the principal pre-approves
 *  its digest in its deploy userOp, so it needs no per-grant passkey. */

/**
 * The interactions grant + its DEL-001 session leaf, built from an INJECTED signer and fetcher.
 *
 * Exists so a re-issue can happen outside the browser (`scripts/reissue-interactions-grants.mts`)
 * without a second copy of the scope list — a copy would drift, and a grant signed over a drifted
 * list is denied per-record with no sign anything is wrong until someone reads their vault.
 */
export async function buildInteractionsGrantForScript(
  principal: string,
  signHash: (digest: Hex) => Promise<string>,
  get: (path: string) => Promise<{ ok?: boolean; address?: string }>,
): Promise<{ grant: DelegationWire; sessionLeaf?: DelegationWire }> {
  const service = INTERACTIONS_SERVICE_SA;
  if (!service) throw new Error('NEXT_PUBLIC_INTERACTIONS_SERVICE_SA is unset — nothing to delegate to');
  const { delegation, digest } = buildInteractionsStruct(principal as Address, service, MCP_SERVER_ID, 60 * 60 * 24 * 365);
  delegation.signature = (await signHash(digest)) as Hex;

  let sessionLeaf: DelegationWire | undefined;
  const sk = await get('/agent/interactions-session-key').catch(() => null);
  if (sk?.ok && sk.address && /^0x[0-9a-fA-F]{40}$/.test(sk.address)) {
    // Spec 408 §2.1 — the DO's session key presents the person's grants to the two service agents only.
    sessionLeaf = toWire(await issueSessionDelegation(principal as Address, sk.address as Address, signHash as (h: Hex) => Promise<Hex>, [service, ...(DELIVERY_SERVICE_SA ? [DELIVERY_SERVICE_SA] : [])]));
  }
  return { grant: toWire(delegation), ...(sessionLeaf ? { sessionLeaf } : {}) };
}

export function buildApprovedInteractionsDelegation(
  principal: Address,
  interactionsServiceSA: Address,
  mcpServerId: string,
  validitySeconds = 60 * 60 * 24 * 365,
): { delegation: Delegation; digest: Hex } {
  const { delegation, digest } = buildInteractionsStruct(principal, interactionsServiceSA, mcpServerId, validitySeconds);
  delegation.signature = APPROVED_HASH_SENTINEL;
  return { delegation, digest };
}

/** The org's managed profile record (`org:profile` — what OrgDetail's steward edits): the org
 *  information a MEMBER may read over their member-access grant (spec 321 W2). */
export const ORG_PROFILE_RESOURCE_SCOPE = 'vault:org.profile' as const; // spec 322 W3 rename

/**
 * spec 321 W2 — the member-access delegation `org → member`, signed by the ORG's custody (the
 * steward's credential) at INVITE time. The delegate is the invitee's person SA — their actual SA
 * for an in-network invite, or the COUNTERFACTUAL email-bootstrap home address for an email invite
 * (the same derivation redeem performs, so the grant activates only if that exact home deploys;
 * against any other account it is inert — fail-closed, no re-targeting). Read-only over the org's
 * shareable profile record; time-boxed; on-chain revocable.
 */
export async function issueOrganizationResourceAccessDelegation(
  orgSA: Address,
  member: Address,
  mcpServerId: string,
  signHash: SignHash,
  validitySeconds = 60 * 60 * 24 * 365,
): Promise<Delegation> {
  const validUntil = Math.floor(Date.now() / 1000) + validitySeconds;
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  let salt = 0n;
  for (const b of bytes) salt = (salt << 8n) | BigInt(b);
  const caveats: Caveat[] = [
    buildVaultRecordScopeCaveat([{ server: mcpServerId, resources: [ORG_PROFILE_RESOURCE_SCOPE], ops: ['read'] }]),
    buildCaveat(CONTRACTS.timestampEnforcer, encodeTimestampTerms(0, validUntil)),
    buildCaveat(CONTRACTS.valueEnforcer, encodeValueTerms(0n)),
  ];
  const d: Delegation = { delegator: orgSA, delegate: member, authority: ROOT_AUTHORITY, caveats, salt, signature: '0x' };
  const digest = hashDelegation(d, CHAIN_ID, CONTRACTS.delegationManager);
  d.signature = await signHash(digest); // the org's custody (the steward's credential) grants member access
  return d;
}

/**
 * P4 record coverage — the workspace/team MEMBERSHIP wire `org → member`, signed by the org's
 * custody at invite time ALONGSIDE the site delegation. The site delegation is reach; this wire is
 * what lets the member READ the org's records: the member plane (directory, conversation index) and
 * the LIBRARY (content catalog + artifacts), which is where field workspaces and teams keep every
 * ws- and team- artifact. Same caveat shape the operator seeds mint — a VAULT_RECORD_SCOPE and NO
 * allowedTargets, which is the SEC-C1 line between member access and stewardship: under both shape
 * tests this is member access and cannot be read as authority to act. The DO evaluates the caveat
 * per resource (`hasScopedAccess`); read-only, time-boxed, on-chain revocable.
 */
export async function issueWorkspaceMembershipAccessDelegation(
  orgSA: Address,
  member: Address,
  mcpServerId: string,
  signHash: SignHash,
  validitySeconds = 60 * 60 * 24 * 365,
): Promise<Delegation> {
  const validUntil = Math.floor(Date.now() / 1000) + validitySeconds;
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  let salt = 0n;
  for (const b of bytes) salt = (salt << 8n) | BigInt(b);
  const caveats: Caveat[] = [
    buildCaveat(CONTRACTS.timestampEnforcer, encodeTimestampTerms(0, validUntil)),
    buildCaveat(CONTRACTS.valueEnforcer, encodeValueTerms(0n)),
    buildVaultRecordScopeCaveat([
      {
        server: mcpServerId,
        resources: ['vault:directory.data', 'vault:conversation.index', 'vault:content.catalog', 'vault:content.artifact.*'],
        ops: ['read'],
      },
    ]),
  ];
  const d: Delegation = { delegator: orgSA, delegate: member, authority: ROOT_AUTHORITY, caveats, salt, signature: '0x' };
  const digest = hashDelegation(d, CHAIN_ID, CONTRACTS.delegationManager);
  d.signature = await signHash(digest); // the org's custody signs the member's record read
  return d;
}

/** The vault-record scope for a library CONTAINER — a folder/skill-bundle subtree (`vault:library.<path>:*`,
 *  a trailing-`*` prefix that anchored-matches every record under it) or a single document
 *  (`vault:library.<id>`, exact). Library resource ids are `container:<path>` / `artifact:<id>`; this maps
 *  them onto the `vault:`-prefixed record family the caveat requires. */
export function libraryVaultScope(input: { folderPath?: string; artifactId?: string }): string {
  if (input.folderPath) return `vault:library.${input.folderPath.replace(/^\/+|\/+$/g, '')}:*`;
  return `vault:library.${input.artifactId}`;
}

/**
 * content-storage §7.2 — the cross-principal library grant `owner → grantee`, signed by the content
 * owner's custody. When an owner shares a FOLDER (or skill-bundle) with another agent — especially a
 * cross-org / external one — the durable `AgenticEntitlementCredentialV1` is paired with this scoped,
 * revocable DELEGATION so the grantee is a *delegate, never a custodian* (ADR-0019). Read-only over the
 * container's record subtree (`vault:library.<path>:*`, so it cascades to everything under the folder,
 * exactly like the entitlement's ancestor-walk); value-0; time-boxed; on-chain revocable.
 */
export async function issueLibraryAccessDelegation(
  ownerSA: Address,
  grantee: Address,
  mcpServerId: string,
  scope: { folderPath?: string; artifactId?: string },
  signHash: SignHash,
  validitySeconds = 60 * 60 * 24 * 365,
): Promise<Delegation> {
  const validUntil = Math.floor(Date.now() / 1000) + validitySeconds;
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  let salt = 0n;
  for (const b of bytes) salt = (salt << 8n) | BigInt(b);
  const caveats: Caveat[] = [
    buildVaultRecordScopeCaveat([{ server: mcpServerId, resources: [libraryVaultScope(scope)], ops: ['read'] }]),
    buildCaveat(CONTRACTS.timestampEnforcer, encodeTimestampTerms(0, validUntil)),
    buildCaveat(CONTRACTS.valueEnforcer, encodeValueTerms(0n)),
  ];
  const d: Delegation = { delegator: ownerSA, delegate: grantee, authority: ROOT_AUTHORITY, caveats, salt, signature: '0x' };
  const digest = hashDelegation(d, CHAIN_ID, CONTRACTS.delegationManager);
  d.signature = await signHash(digest); // the content owner's custody grants the delegate read access
  return d;
}

/**
 * spec 321 W1 — the membership delegation `member → org`, signed by the member's connection
 * custodian at invite ACCEPT (spec 246's deferred person→org leg). Read-only over the member's
 * shareable profile record (`vault:member.profile`) — the org can render its member roster from
 * each member's own vault (spec 247: it holds a delegation, never a copy) and NOTHING else.
 * Time-boxed, value 0, on-chain revocable.
 */
export async function issueMemberProfileAccessDelegation(
  member: Address,
  orgSA: Address,
  mcpServerId: string,
  signHash: SignHash,
  validitySeconds = 60 * 60 * 24 * 365,
): Promise<Delegation> {
  const validUntil = Math.floor(Date.now() / 1000) + validitySeconds;
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  let salt = 0n;
  for (const b of bytes) salt = (salt << 8n) | BigInt(b);
  const caveats: Caveat[] = [
    // Per-org record (spec 322 W3d): the org reads ONLY the profile card the member keyed to IT.
    buildVaultRecordScopeCaveat([{ server: mcpServerId, resources: [`${MEMBER_PROFILE_RESOURCE_SCOPE}:${orgSA.toLowerCase()}`], ops: ['read'] }]),
    buildCaveat(CONTRACTS.timestampEnforcer, encodeTimestampTerms(0, validUntil)),
    buildCaveat(CONTRACTS.valueEnforcer, encodeValueTerms(0n)),
  ];
  const d: Delegation = { delegator: member, delegate: orgSA, authority: ROOT_AUTHORITY, caveats, salt, signature: '0x' };
  const digest = hashDelegation(d, CHAIN_ID, CONTRACTS.delegationManager);
  d.signature = await signHash(digest); // the member's connection custodian consents to org membership
  return d;
}

// ─── spec 329 §2.1 — the consultability delegation (member → org) ─────────────────────────────

/** The consult A2A OFFERING — an A2A `AgentSkill` advertisement, not a capability claim or a playbook
 *  (facet-registries.md §7); `CONSULT_SKILL` is the wire name and is immutable. (spec 329 §3.)
 *  Kept as a local literal (this transport-agnostic module
 *  takes no fabric/a2a dependency — the INBOX_DELIVERY_RESOURCE_SCOPE precedent); demo-a2a's
 *  `authorizeA2aMessage` derives the same selector from the same string at the member's gate. */
export const CONSULT_SKILL = 'discussion.consult' as const;

/** 4-byte A2A offering selector: keccak256(utf8(skill))[:4] — byte-for-byte the
 *  `@agenticprimitives/a2a` `skillSelector` the member's gate decodes against. */
export function consultSkillSelector(): Hex {
  return keccak256(toBytes(CONSULT_SKILL)).slice(0, 10) as Hex;
}

/** Default consultability lifetime (spec 329 §2.1): 180 days; re-opt-in refreshes. */
export const CONSULT_GRANT_VALIDITY_SECONDS = 180 * 24 * 60 * 60;

/**
 * spec 329 §2.1 — the OPT-IN consultability delegation `member → org`, signed by the MEMBER's
 * connection custodian at the Home ceremony (spec 321's third, member-signed leg). Authorizes the
 * ORG (the delegate — never a router service account) to submit A2A tasks to the MEMBER's agent
 * for the `discussion.consult` skill ONLY:
 *   allowedTargets = [the member SA]  (the grant is non-replayable against another agent),
 *   allowedMethods = [consult selector]  (NEVER A2A_ANY_SKILL),
 *   timestamp-bounded (default 180 days), on-chain revocable (revocation is immediate at the
 *   member's gate regardless of what the org has cached).
 * The member's A2A gate (`authorizeA2aMessage`, spec 269 FR-4) re-verifies ALL of it per message —
 * this delegation IS the authority; the listing's `consultable` flag is only the routing hint.
 */
export async function issueConsultabilityDelegation(
  member: Address,
  orgSA: Address,
  signHash: SignHash,
  validitySeconds = CONSULT_GRANT_VALIDITY_SECONDS,
): Promise<Delegation> {
  const validUntil = Math.floor(Date.now() / 1000) + validitySeconds;
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  let salt = 0n;
  for (const b of bytes) salt = (salt << 8n) | BigInt(b);
  const caveats: Caveat[] = [
    buildCaveat(CONTRACTS.timestampEnforcer, encodeTimestampTerms(0, validUntil)),
    buildCaveat(CONTRACTS.allowedTargetsEnforcer, encodeAllowedTargetsTerms([member])),
    buildCaveat(CONTRACTS.allowedMethodsEnforcer, encodeAllowedMethodsTerms([consultSkillSelector()])),
  ];
  const d: Delegation = { delegator: member, delegate: orgSA, authority: ROOT_AUTHORITY, caveats, salt, signature: '0x' };
  const digest = hashDelegation(d, CHAIN_ID, CONTRACTS.delegationManager);
  d.signature = await signHash(digest); // the member's connection custodian consents to consultation
  return d;
}

/** 4-byte A2A offering selector for ANY skill name — the same derivation `consultSkillSelector` and
 *  `operationalIntentSelectors` use, factored out so a new rail cannot invent a third. */
export function a2aSkillSelector(skill: string): Hex {
  return keccak256(toBytes(skill)).slice(0, 10) as Hex;
}

// ─── The ARCHETYPE DISPATCH grant (host org → calling org) ────────────────────────────────────

/** The A2A method that addresses an archetype — `ontologist` → `archetype.ontologist`. Must derive
 *  identically to demo-a2a's `archetypeMethod`, or a grant authorizes a method nobody calls. */
export function archetypeMethod(slug: string): string {
  return `archetype.${slug}`;
}

/** Selectors for a SET of archetypes. One entry per role, never a wildcard — see below. */
export function archetypeMethodSelectors(slugs: readonly string[]): Hex[] {
  return slugs.map((s) => a2aSkillSelector(archetypeMethod(s)));
}

/** 90 days. Operational rather than structural — this authorizes one org to spend another's agent
 *  budget, so it is re-minted often rather than held for a year like a naming grant. */
export const ARCHETYPE_GRANT_VALIDITY_SECONDS = 90 * 24 * 60 * 60;

/**
 * Archetype methods an org's signing wire covers by default — the ontology-engineering roster,
 * which is the only one deployed.
 *
 * A COUPLING WORTH KNOWING: this wire is minted at the routing-enable ceremony, but the GRANTS that
 * make a method usable can arrive later. A grant for a role outside this list is a credential the
 * org cannot sign for, and the failure appears at the HOST's gate as an invalid signature rather
 * than as "re-run your ceremony". Naming the roster up front makes the common case work without a
 * re-mint; an org dispatching to a role outside it must re-enable routing to widen its wire.
 *
 * Listing a method here grants nothing. The wire says what this org CAN SIGN FOR; the host's grant
 * says what it MAY invoke. Both are required, and neither implies the other.
 */
export const DEFAULT_DISPATCH_ARCHETYPES: readonly string[] = [
  'domain-analyst', 'cluster-architect', 'information-architect', 'ontologist', 'taxonomist',
  'ontology-reviewer', 'ontology-creation-planner', 'spec-librarian', 'exemplar-curator',
];

/**
 * The archetype dispatch delegation `host org → calling org`.
 *
 * DIRECTION IS THE THING TO GET RIGHT, and it is the opposite of intuition. The delegator is the org
 * that HOSTS the archetypes — the one whose agent will do the work and pay for it — because in A2A
 * the recipient's gate verifies a delegation whose delegator IS the recipient. This is an OPT-IN by
 * the host ("ontology-engineering agrees to be asked"), exactly like `issueConsultabilityDelegation`
 * one relationship over, where the member opts in to being consulted. A grant minted the other way
 * round would let a caller authorize itself, which is the authority-in-a-message shape ADR-0041
 * forbids, and the host's gate would reject it anyway.
 *
 *   allowedTargets = [the host org]      — non-replayable against any other agent,
 *   allowedMethods = one selector PER ARCHETYPE  — never A2A_ANY_SKILL,
 *   timestamp-bounded (90 days), on-chain revocable — revocation is immediate at the host's gate
 *   regardless of what the caller has cached.
 *
 * PER-ARCHETYPE SELECTORS ARE THE WHOLE POINT of naming archetypes as distinct A2A methods. A host
 * can grant its Ontologist and its Reviewer while withholding its Creation Planner, because
 * `allowedMethods` is a `bytes4[]` the on-chain enforcer checks member-wise. A single method taking
 * the role as an argument would have collapsed this to all-or-nothing, and the argument would have
 * been caller-supplied.
 *
 * The host's A2A gate (`authorizeA2aMessage`) re-verifies all of it per message. This delegation IS
 * the authority; nothing about the caller's identity or its endeavor grants it anything here.
 */
export async function issueArchetypeDispatchDelegation(
  hostOrg: Address,
  callerOrg: Address,
  archetypeSlugs: readonly string[],
  signHash: SignHash,
  validitySeconds = ARCHETYPE_GRANT_VALIDITY_SECONDS,
): Promise<Delegation> {
  const slugs = [...new Set(archetypeSlugs.map((s) => s.trim().toLowerCase()).filter(Boolean))];
  if (slugs.length === 0) {
    // An empty method list would encode an allowedMethods caveat that permits NOTHING, which reads
    // at the gate as a mysterious refusal rather than as a grant nobody meant to mint.
    throw new Error('archetype dispatch grant needs at least one archetype — an empty grant authorizes nothing');
  }
  for (const s of slugs) {
    if (!/^[a-z0-9][a-z0-9-]{1,60}$/.test(s)) throw new Error(`invalid archetype slug "${s}"`);
  }
  if (hostOrg.toLowerCase() === callerOrg.toLowerCase()) {
    // Self-dispatch needs no grant (the host is already the principal), and minting one would put a
    // revocable credential in the path of work that must never depend on it.
    throw new Error('host and caller are the same org — an archetype dispatch grant is not needed for self-dispatch');
  }

  const validUntil = Math.floor(Date.now() / 1000) + validitySeconds;
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  let salt = 0n;
  for (const b of bytes) salt = (salt << 8n) | BigInt(b);
  const caveats: Caveat[] = [
    buildCaveat(CONTRACTS.timestampEnforcer, encodeTimestampTerms(0, validUntil)),
    buildCaveat(CONTRACTS.allowedTargetsEnforcer, encodeAllowedTargetsTerms([hostOrg])),
    buildCaveat(CONTRACTS.allowedMethodsEnforcer, encodeAllowedMethodsTerms(archetypeMethodSelectors(slugs))),
  ];
  const d: Delegation = { delegator: hostOrg, delegate: callerOrg, authority: ROOT_AUTHORITY, caveats, salt, signature: '0x' };
  const digest = hashDelegation(d, CHAIN_ID, CONTRACTS.delegationManager);
  d.signature = await signHash(digest);   // the HOST's custodian consents to being dispatched to
  return d;
}

/**
 * The SERVICE-AGENT WIRE `identity → the relying service's KMS key` (ADR-0019; the agent-rule
 * `service-agent-signing.md`). What lets a service sign AS a named agent it does NOT custody.
 *
 * The identity (e.g. `skills-agent.impact`) is custodied by its owner, here, in this ceremony. The
 * delegate is the service's KMS SIGNING KEY — the address a raw ECDSA signature recovers to, NOT the
 * service's agent account. Getting that wrong produces a wire that verifies nowhere, so the service
 * reports the address rather than the operator typing one.
 *
 * Same shape as `issueConsultabilityDelegation` one relationship over, and the same refusals:
 *   allowedTargets = [the identity]     usable solely to act AS this identity, never another,
 *   allowedMethods = [one skill]        NEVER A2A_ANY_SKILL — a wire is per-rail, so a leaked key
 *                                       signs one kind of message and nothing else,
 *   timestamp-bounded (90 days), on-chain revocable — the custodian's revoke kills it at every gate
 *                                       immediately, which is the property custody-by-the-service
 *                                       cannot offer at all.
 */
export const SERVICE_AGENT_WIRE_VALIDITY_SECONDS = 90 * 24 * 60 * 60;

export async function issueServiceAgentWireDelegation(
  identity: Address,
  delegateKey: Address,
  skills: string | readonly string[],
  signHash: SignHash,
  validitySeconds = SERVICE_AGENT_WIRE_VALIDITY_SECONDS,
): Promise<Delegation> {
  // A PINNED SET, not a single skill. A rail is usually more than one operation — submitting work
  // and reading its state are different skills — and a wire per skill meant a ceremony per skill.
  // The set is still an enumeration the custodian approved; `A2A_ANY_SKILL` remains refused, which
  // is the line between "these operations" and "anything this agent can do".
  const list = (typeof skills === 'string' ? [skills] : [...skills]).filter(Boolean);
  if (list.length === 0) throw new Error('a service-agent wire must name at least one skill');
  const validUntil = Math.floor(Date.now() / 1000) + validitySeconds;
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  let salt = 0n;
  for (const b of bytes) salt = (salt << 8n) | BigInt(b);
  const caveats: Caveat[] = [
    buildCaveat(CONTRACTS.timestampEnforcer, encodeTimestampTerms(0, validUntil)),
    buildCaveat(CONTRACTS.allowedTargetsEnforcer, encodeAllowedTargetsTerms([identity])),
    buildCaveat(CONTRACTS.allowedMethodsEnforcer, encodeAllowedMethodsTerms(list.map(a2aSkillSelector))),
  ];
  const d: Delegation = { delegator: identity, delegate: delegateKey, authority: ROOT_AUTHORITY, caveats, salt, signature: '0x' };
  const digest = hashDelegation(d, CHAIN_ID, CONTRACTS.delegationManager);
  d.signature = await signHash(digest); // the identity's custodian authorizes the service's key
  return d;
}

/** The A2A skills an Operational Intent grant may carry. Named here so the minting side and the
 *  org's gate derive the SAME selectors from the SAME strings — a selector computed from a drifting
 *  string list is a grant that silently authorizes nothing.
 *
 *  THE OTHER COPY IS `ENDEAVOR_REQUEST_SKILL_ID` in demo-a2a (`src/endeavor-intake.ts`), which is the
 *  registered handler these selectors have to reach. Two copies because neither app depends on the
 *  other (the CONSULT_SKILL precedent); demo-a2a's test pins the derived selector
 *  (`endeavor.request` → `0x9db527f0`), so a change there fails loudly. A change HERE does not —
 *  edit both, or every minted grant stops matching a gate that looks correct.
 *
 *  Only `endeavor.request` is a registered skill today. `adoptPlan` is steward-gated at the reducer
 *  and `state` has no handler yet, so a message naming either is rejected as `unknown skill` — inert,
 *  not dangerous, and the reason the grant is minted with room for them.
 *
 *  THE RELAY PAIR lets a holder ask this org to dispatch to a SPECIALIST on another organization,
 *  and read the result back. It does NOT widen where the org can reach: the relay forwards only to
 *  hosts and archetypes the org already holds its own grant for, so a holder gains the org's reach
 *  and never more. Two methods because the holder is not a party to the task the host creates.
 *
 *  This list is GLOBAL — every app that mints an operational grant mints these too. Acceptable
 *  because a selector naming a skill the holder cannot usefully invoke is inert (see above), and
 *  because per-app selector sets would put the authorization surface in a config file where a typo
 *  is silent. Revisit if an app ever needs a NARROWER grant than this. */
export const OPERATIONAL_INTENT_SKILLS = [
  'endeavor.request', 'endeavor.adoptPlan', 'endeavor.state',
  'archetype.relay', 'archetype.relayResult',
] as const;

/** 4-byte A2A offering selectors for those skills — keccak256(utf8(skill))[:4], the same derivation
 *  `consultSkillSelector` uses and the same one `authorizeA2aMessage` decodes against. */
export function operationalIntentSelectors(): Hex[] {
  return OPERATIONAL_INTENT_SKILLS.map((s) => keccak256(toBytes(s)).slice(0, 10) as Hex);
}

/** 90 days. Operational rather than structural: this authorizes an agent to submit work, so it is
 *  re-minted often rather than held for a year like the naming/relationship site grant. */
export const OPERATIONAL_INTENT_VALIDITY_SECONDS = 90 * 24 * 60 * 60;

/**
 * The OPERATIONAL INTENT grant `org → agent` — see skills repo `docs/operational-intent-grant.md`.
 *
 * Authorizes a named agent (e.g. skills-a2a's service SA) to submit endeavor intents to THIS org's
 * A2A endpoint and follow their progress, and nothing else. It is the concrete form of `at:Mandate`:
 * what a `at:PlanStep` that `at:requiresMandate` presents at `at:invokedAtEndpoint`.
 *
 * Deliberately the same shape as `issueConsultabilityDelegation` one relationship over — that grant
 * is the precedent, including its refusals:
 *   allowedTargets = [the org SA]        the grant is non-replayable against another organization,
 *   allowedMethods = [endeavor selectors] NEVER A2A_ANY_SKILL — an any-skill grant to a dispatcher
 *                                        would also authorize rewriting the org's playbook, which
 *                                        changes what every one of its agent turns obeys,
 *   value = 0                            never moves funds,
 *   timestamp-bounded, on-chain revocable — revocation is immediate at the org's gate whatever the
 *                                        holder has cached.
 *
 * The org's A2A gate (`authorizeA2aMessage`, spec 269 FR-4) re-verifies ALL of it per message: this
 * delegation IS the authority, not a hint.
 *
 * NOTE the delegate must be a DEDICATED service SA. The shared registry delegate that relying apps
 * name in `whitelabel/config.ts` is used by a dozen entries; granting operational authority to it
 * would grant it to every app on that address.
 */
export async function issueOperationalIntentDelegation(
  orgSA: Address,
  agentSA: Address,
  signHash: SignHash,
  validitySeconds = OPERATIONAL_INTENT_VALIDITY_SECONDS,
): Promise<Delegation> {
  const validUntil = Math.floor(Date.now() / 1000) + validitySeconds;
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  let salt = 0n;
  for (const b of bytes) salt = (salt << 8n) | BigInt(b);
  const caveats: Caveat[] = [
    buildCaveat(CONTRACTS.timestampEnforcer, encodeTimestampTerms(0, validUntil)),
    buildCaveat(CONTRACTS.allowedTargetsEnforcer, encodeAllowedTargetsTerms([orgSA])),
    buildCaveat(CONTRACTS.allowedMethodsEnforcer, encodeAllowedMethodsTerms(operationalIntentSelectors())),
    buildCaveat(CONTRACTS.valueEnforcer, encodeValueTerms(0n)),
  ];
  const d: Delegation = { delegator: orgSA, delegate: agentSA, authority: ROOT_AUTHORITY, caveats, salt, signature: '0x' };
  const digest = hashDelegation(d, CHAIN_ID, CONTRACTS.delegationManager);
  d.signature = await signHash(digest); // the org's custody (the steward's credential) consents
  return d;
}

/** The approved-hash variant, for folding into the org-create deploy userOp — one more digest in the
 *  batch, so the member is not asked for an extra signature. Mirrors `buildApprovedSiteDelegation`. */
export function buildApprovedOperationalIntentDelegation(
  orgSA: Address,
  agentSA: Address,
  validitySeconds = OPERATIONAL_INTENT_VALIDITY_SECONDS,
): { delegation: Delegation; digest: Hex } {
  const validUntil = Math.floor(Date.now() / 1000) + validitySeconds;
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  let salt = 0n;
  for (const b of bytes) salt = (salt << 8n) | BigInt(b);
  const caveats: Caveat[] = [
    buildCaveat(CONTRACTS.timestampEnforcer, encodeTimestampTerms(0, validUntil)),
    buildCaveat(CONTRACTS.allowedTargetsEnforcer, encodeAllowedTargetsTerms([orgSA])),
    buildCaveat(CONTRACTS.allowedMethodsEnforcer, encodeAllowedMethodsTerms(operationalIntentSelectors())),
    buildCaveat(CONTRACTS.valueEnforcer, encodeValueTerms(0n)),
  ];
  const d: Delegation = { delegator: orgSA, delegate: agentSA, authority: ROOT_AUTHORITY, caveats, salt, signature: '0x' };
  const digest = hashDelegation(d, CHAIN_ID, CONTRACTS.delegationManager);
  d.signature = APPROVED_HASH_SENTINEL;
  return { delegation: d, digest };
}

/** One year — structural rather than operational: the workspace agent HOLDS this grant and reads the
 *  org's record in place; the org's exit is the on-chain revoke, not expiry. */
export const ORG_READ_GRANT_VALIDITY_SECONDS = 365 * 24 * 60 * 60;

/**
 * The ORG READ grant `org → app workspace agent` (whitelabel `org_read_grant`) — a vault-record-scope,
 * READ-ONLY delegation over ONE record family (e.g. `vault:gather27:listing`), so an app whose
 * workspace lists member organizations reads each org's record IN PLACE instead of keeping a copy.
 *
 * Minted at the org-connect ceremony because that is the only moment the org's custody is in the loop
 * for every credential family alike — KMS (Google/email), passkey, wallet, and demo custody all sign
 * here. A relying app cannot mint it later: persona-sign covers demo accounts only, and the app never
 * holds the org's key (which is the point).
 *
 * Same refusals as the per-app person read grant (read-grants.ts): explicit resources (the caveat
 * builder refuses `vault:*`), ops read-only, timestamp-bounded, value 0, on-chain revocable.
 */
export function buildApprovedOrgReadDelegation(
  orgSA: Address,
  delegate: Address,
  scope: { server: string; resources: readonly string[] },
  validitySeconds = ORG_READ_GRANT_VALIDITY_SECONDS,
): { delegation: Delegation; digest: Hex } {
  const validUntil = Math.floor(Date.now() / 1000) + validitySeconds;
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  let salt = 0n;
  for (const b of bytes) salt = (salt << 8n) | BigInt(b);
  const caveats: Caveat[] = [
    buildCaveat(CONTRACTS.timestampEnforcer, encodeTimestampTerms(0, validUntil)),
    buildCaveat(CONTRACTS.valueEnforcer, encodeValueTerms(0n)),
    buildVaultRecordScopeCaveat([{ server: scope.server, resources: [...scope.resources], ops: ['read'] }]),
  ];
  const d: Delegation = { delegator: orgSA, delegate, authority: ROOT_AUTHORITY, caveats, salt, signature: '0x' };
  const digest = hashDelegation(d, CHAIN_ID, CONTRACTS.delegationManager);
  d.signature = APPROVED_HASH_SENTINEL;
  return { delegation: d, digest };
}

/** The direct-signature variant, for the KMS org path: bootstrap-org deploys server-side, so there is
 *  no deploy batch to fold the digest into — the C_sub key signs right after, still zero prompts. */
export async function issueOrgReadDelegation(
  orgSA: Address,
  delegate: Address,
  scope: { server: string; resources: readonly string[] },
  signHash: SignHash,
  validitySeconds = ORG_READ_GRANT_VALIDITY_SECONDS,
): Promise<Delegation> {
  const { delegation, digest } = buildApprovedOrgReadDelegation(orgSA, delegate, scope, validitySeconds);
  delegation.signature = await signHash(digest);
  return delegation;
}

// ─── spec 345 — the SELF VAULT GRANT (delegator = delegate = personSA) ────────────────────────

/** The scope a relying app's whitelabel entry may declare for its self-vault grant — fixed
 *  server-side, never client-request-supplied (mirrors `org_read_grant`'s scope shape). */
export interface SelfVaultGrantConfig {
  readonly server: string;
  readonly resources: readonly string[];
  readonly ops: readonly ('read' | 'write')[];
}

/** One year — same structural reasoning as ORG_READ_GRANT_VALIDITY_SECONDS: the app holds this
 *  grant and reads/writes the person's own record in place; the person's exit is the on-chain
 *  revoke, not expiry. */
export const SELF_VAULT_GRANT_VALIDITY_SECONDS = 365 * 24 * 60 * 60;

/**
 * The SELF VAULT grant `personSA → personSA` (whitelabel `self_vault_grant`) — a vault-record-
 * scope delegation over ONE record family, so a person can publish/edit content under their OWN
 * identity with no organization, team, or stewardship relationship involved at all.
 *
 * Minted in the SAME plain sign-in ceremony every relying app already runs (`givePermission`,
 * template `site-login`) — no separate ceremony trip, works for every custody family (KMS /
 * passkey / wallet / demo) the same way `org_read_grant` does at org-connect. Read+write is
 * allowed (unlike `org_read_grant`'s read-only) because the delegate IS the delegator: the person
 * is granting themselves access to their own record, never exposing it to a third party.
 *
 * THE RULE THIS EXISTS TO ENFORCE: this function and its caller MUST NEVER call
 * `projectStewardRelationshipToVault` or write anything to `impact-relationships`. A person
 * granting themselves access to their own vault is not "stewarding an org" — conflating the two
 * is exactly the incident this spec (345) was written to close (a person's own address showing up
 * in their own org list because a self-referential stewardship entry got written for them).
 */
export function buildApprovedSelfVaultGrant(
  personSA: Address,
  scope: SelfVaultGrantConfig,
  validitySeconds = SELF_VAULT_GRANT_VALIDITY_SECONDS,
): { delegation: Delegation; digest: Hex } {
  const validUntil = Math.floor(Date.now() / 1000) + validitySeconds;
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  let salt = 0n;
  for (const b of bytes) salt = (salt << 8n) | BigInt(b);
  const caveats: Caveat[] = [
    buildCaveat(CONTRACTS.timestampEnforcer, encodeTimestampTerms(0, validUntil)),
    buildCaveat(CONTRACTS.valueEnforcer, encodeValueTerms(0n)),
    buildVaultRecordScopeCaveat([{ server: scope.server, resources: [...scope.resources], ops: [...scope.ops] }]),
  ];
  const d: Delegation = { delegator: personSA, delegate: personSA, authority: ROOT_AUTHORITY, caveats, salt, signature: '0x' };
  const digest = hashDelegation(d, CHAIN_ID, CONTRACTS.delegationManager);
  d.signature = APPROVED_HASH_SENTINEL;
  return { delegation: d, digest };
}

/** The direct-signature variant, for a person who already exists (the common case — gather27's
 *  individual host is signing in, not being freshly deployed): no deploy batch to fold the digest
 *  into, so `signHash` signs it directly, same as `issueOrgReadDelegation`'s KMS-path sibling. */
export async function issueSelfVaultGrant(
  personSA: Address,
  scope: SelfVaultGrantConfig,
  signHash: SignHash,
  validitySeconds = SELF_VAULT_GRANT_VALIDITY_SECONDS,
): Promise<Delegation> {
  const { delegation, digest } = buildApprovedSelfVaultGrant(personSA, scope, validitySeconds);
  delegation.signature = await signHash(digest);
  return delegation;
}

/**
 * spec 329 §3.1 — the ORG consult wire `org → interactions-session key`, signed by the ORG's
 * custody (the steward's credential) at the ROUTING-ENABLE ceremony. Resolves the caller-signature
 * gap: the org's runtime holds no org key, so consult-rail `message/send` sender signatures and
 * `tasks/get` caller signatures are ECDSA by the interactions-session KMS key, presented
 * session-wrapped WITH this wire — the member's gate verifies the wire (ERC-1271 against the org
 * + unrevoked on-chain + consult-selector-only + timestamp) per message. NARROW by construction:
 *   allowedMethods = [discussion.consult selector]  (NEVER any-skill — unusable for anything else),
 *   allowedTargets = [the org SA]                   (usable solely to act AS this org),
 *   timestamp-bounded (180 days, the consultability symmetry; re-enable refreshes),
 *   on-chain revocable (steward revoke kills routing at every member's gate immediately).
 * Custodied in the org's InteractionsDO (spec 322 §2 — a stored wire lives with its delegate
 * service); no raw key ever rests server-side.
 */
export async function issueOrgConsultRoutingDelegation(
  orgSA: Address,
  interactionsSessionKey: Address,
  signHash: SignHash,
  validitySeconds = CONSULT_GRANT_VALIDITY_SECONDS,
  /**
   * Archetype roles this org may DISPATCH TO on other organizations. Their methods join the consult
   * selector in the SAME wire.
   *
   * TWO CREDENTIALS ARE INVOLVED AND THEY ARE EASY TO CONFLATE — this is the one that was missed.
   * The archetype dispatch GRANT (host → caller) says the caller MAY invoke a method. This wire says
   * the org CAN SIGN AS ITSELF for that method. A caller holding a perfect grant still cannot
   * dispatch if its own wire names only `discussion.consult`, because the host's gate verifies the
   * session-wrapped signature against the wire and finds the method absent. Grants without this are
   * a credential that verifies nowhere.
   *
   * One wire rather than two, because a second wire for the same delegate would double the ceremony
   * and the revocation surface for no separation — `allowedMethods` already enumerates, and
   * `checkSessionWireShape` pins by MEMBERSHIP, so naming more methods narrows nothing about consult.
   * Still never the any-skill sentinel: every method is named.
   */
  dispatchArchetypes: readonly string[] = [],
): Promise<Delegation> {
  const validUntil = Math.floor(Date.now() / 1000) + validitySeconds;
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  let salt = 0n;
  for (const b of bytes) salt = (salt << 8n) | BigInt(b);
  const caveats: Caveat[] = [
    buildCaveat(CONTRACTS.timestampEnforcer, encodeTimestampTerms(0, validUntil)),
    buildCaveat(CONTRACTS.allowedTargetsEnforcer, encodeAllowedTargetsTerms([orgSA])),
    buildCaveat(CONTRACTS.allowedMethodsEnforcer, encodeAllowedMethodsTerms([
      consultSkillSelector(),
      ...archetypeMethodSelectors([...new Set(dispatchArchetypes.map((a) => a.trim().toLowerCase()).filter(Boolean))]
        .filter((a) => /^[a-z0-9][a-z0-9-]{1,60}$/.test(a))),
    ])),
  ];
  const d: Delegation = { delegator: orgSA, delegate: interactionsSessionKey, authority: ROOT_AUTHORITY, caveats, salt, signature: '0x' };
  const digest = hashDelegation(d, CHAIN_ID, CONTRACTS.delegationManager);
  d.signature = await signHash(digest); // the org's custody (the steward's credential) authorizes routing
  return d;
}

// ─── spec 272/243 — x402 payment delegation (treasury → treasury) ─────────────────────────────

/** DelegationManager sentinel: delegate = 0xa11 ⇒ ANY redeemer may redeem (the PaymentEnforcer still
 *  fully gates every charge — payee-bound, capped, transfer-only). Use this for x402 PUSH payments
 *  where the PAYER (reader) drives the redemption at access time; the funds still move treasury →
 *  treasury (payer-treasury → the caveat's payee). For PULL payments (subscriptions, metered post-pay)
 *  pass `delegate = the payee treasury` instead, so the provider redeems on its own schedule. */
export const OPEN_DELEGATION = '0x0000000000000000000000000000000000000a11' as Address;

/** Issue an x402 payment delegation from the person's TREASURY SA. The custodian never appears: the
 *  person's treasury is custodied by the SAME ROOT credential as the person SA (MAM-D2), so `signHash`
 *  — the same passkey/wallet/social signer used for the site delegation — authorizes it; the treasury's
 *  ERC-1271 validates it at redemption. Signed ONCE at connect, stored in a vault, redeemed many times
 *  within the caveats (no held key, no per-charge signature). USDC always lands at `payee`.
 *
 *  `delegate`: OPEN_DELEGATION for x402 push (the reader redeems) | a payee treasury for pull/subscription. */
export async function issuePaymentDelegation(
  payerTreasury: Address,
  delegate: Address,
  payee: Address,
  signHash: SignHash,
  opts: {
    asset: Address;
    maxAmountPerCharge: bigint;
    maxAggregate: bigint;
    maxRedemptionsPerWindow?: number;
    windowSeconds?: number;
    validitySeconds?: number;
  },
): Promise<Delegation> {
  const validUntil = Math.floor(Date.now() / 1000) + (opts.validitySeconds ?? 60 * 60 * 24 * 365);
  const caveats = buildPaymentMandateCaveats({
    enforcers: {
      payment: CONTRACTS.paymentEnforcer,
      timestamp: CONTRACTS.timestampEnforcer,
      allowedTargets: CONTRACTS.allowedTargetsEnforcer,
      allowedMethods: CONTRACTS.allowedMethodsEnforcer,
    },
    payee,
    asset: opts.asset,
    maxAmountPerCharge: opts.maxAmountPerCharge,
    maxAggregate: opts.maxAggregate,
    maxRedemptionsPerWindow: opts.maxRedemptionsPerWindow ?? 1000,
    windowSeconds: opts.windowSeconds ?? 3600,
    validUntil,
  });
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  let salt = 0n;
  for (const b of bytes) salt = (salt << 8n) | BigInt(b);
  const d: Delegation = {
    delegator: payerTreasury,
    delegate,
    authority: ROOT_AUTHORITY,
    caveats,
    salt,
    signature: '0x',
  };
  const digest = hashDelegation(d, CHAIN_ID, CONTRACTS.delegationManager);
  d.signature = await signHash(digest); // SAME root credential that signs the site delegation
  return d;
}

// ─── spec 270 v4 W2 — the DEL-001 session-delegation leaf (the connect-ceremony emission) ─────

// The session keypair is generated by the RELYING APP (it holds the private key on its own origin);
// the home only receives the public `sessionKeyAddress` and signs the leaf below. The home therefore
// never mints or holds a session private key (no cross-origin key transport — spec 270 v4 secure design).

/**
 * The DEL-001 interactions session-leaf lifetime. It is signed ONCE — at the moment a steward enables storage,
 * the one moment the steward is present — and binds the serving plane's (KMS-custodied, server-held) interactions
 * session key to a principal's grant.
 *
 * TWO TIERS, because the two cases differ in who signs and whether they return (org-leaf-decay, 2026-10-03):
 *   · A PERSON's own leaf: the connected user re-signs it every time they open their Home (the self-heal in
 *     session.tsx + activateInteractionsIfNeeded), so a SHORT 12h window is correct hygiene and changes nothing —
 *     they are present each session. This stays 12h.
 *   · An ORG's leaf: signed by a STEWARD — possibly a different person — who may not come back for weeks and does
 *     not want to be hassled. An org has no portal and cannot self-renew, so a 12h leaf guaranteed every org went
 *     dark 12h after enable, 409-storming its Work / Discussions / Library / inbox with a bare "auth failed". The
 *     short window bought little for a KMS-held key (its leak == a KMS compromise, which no leaf TTL survives) and
 *     cost a live org a day. So an org's leaf lasts as long as the authority grant it rides (1y; it can never
 *     usefully outlive the grant anyway) — signed once, by the steward, when they enable storage.
 * Both are env-overridable. The DO's `status.current` audience check + the endeavor `needsReEnable` pre-flight
 * catch the RARE lapse a long TTL can't cover (the DO's session key rotating, or a pre-408 leaf) and make it a
 * one-signature re-enable instead of a silent failure.
 */
export const PERSON_INTERACTIONS_SESSION_LEAF_TTL_SECONDS =
  Number(process.env.NEXT_PUBLIC_INTERACTIONS_LEAF_TTL_SECONDS) || 60 * 60 * 12;
/** The ORG/third-party-steward leaf lifetime (see the note above): long, because the steward who signs it may
 *  not return for weeks and nothing else re-signs it. Overridable per deployment. */
export const ORG_INTERACTIONS_SESSION_LEAF_TTL_SECONDS =
  Number(process.env.NEXT_PUBLIC_ORG_INTERACTIONS_LEAF_TTL_SECONDS) || 60 * 60 * 24 * 365;
/** Spec 423 §2.1 route A — the PRE-APPROVED LEAF LADDER depth for an org. The steward signs this many session
 *  leaves at once (windows tiling forward by the org TTL), so a live rung exists for rungs × TTL — years of
 *  autonomy from a single signing, with no new security surface (the DO just picks the live rung). A person's
 *  leaf is always a single rung (they re-sign each login). Env-tunable. */
export const ORG_INTERACTIONS_SESSION_LEAF_LADDER_RUNGS =
  Math.max(1, Math.min(8, Number(process.env.NEXT_PUBLIC_ORG_INTERACTIONS_LEAF_LADDER_RUNGS) || 3));

/** Issue the DEL-001 session-delegation leaf `personAgent → sessionKey`, signed by the SAME ROOT
 *  credential (`signHash`) that signs the site delegation at connect. Bound to the person SA (the
 *  canonical identity), so it works for whatever credential the member connected with (passkey / wallet /
 *  Google-KMS); the verifier validates it via the UniversalSignatureValidator (spec 270 W1). The relying
 *  app holds the session key + this leaf, signs tokens with the key, and presents the chain. */
export async function issueSessionDelegation(
  personAgent: Address,
  sessionKeyAddress: Address,
  signHash: SignHash,
  /** Spec 408 §2.1 — the delegates this session key may present the principal's delegations to. */
  presentsTo: readonly Address[],
  validitySeconds = PERSON_INTERACTIONS_SESSION_LEAF_TTL_SECONDS,
): Promise<Delegation> {
  const { leaf, digest } = buildSessionDelegation({
    delegator: personAgent,
    sessionKeyAddress,
    presentsTo,
    validUntil: Math.floor(Date.now() / 1000) + validitySeconds,
    enforcers: { timestamp: CONTRACTS.timestampEnforcer, value: CONTRACTS.valueEnforcer },
    chainId: CHAIN_ID,
    delegationManager: CONTRACTS.delegationManager,
  });
  leaf.signature = await signHash(digest); // the ROOT credential authorizes the session key
  return leaf;
}

/** spec 253 + 270 v4 — the DEL-001 session leaf WITHOUT an off-chain signature (B4). Same struct + EIP-712
 *  `digest` as `issueSessionDelegation`, but the wire signature is the `0x03` approved-hash sentinel, so the
 *  caller batches `approvedHashRegistry.approveHash(digest)` into the DELEGATOR (person SA) userOp alongside
 *  the site grant — ONE signature approves both instead of one off-chain sign per leaf. The verifier validates
 *  it identically to a signed leaf: `UniversalSignatureValidator.isValidSig(personSA, digest, 0x03)` → the SA's
 *  ERC-1271 `0x03` branch → `ApprovedHashRegistry.isApproved`. The digest excludes the signature field, so it
 *  is identical to what the relayer + demo-mcp client-mint verifier recompute (spec 270 W1). */
export function buildApprovedSessionDelegation(
  personAgent: Address,
  sessionKeyAddress: Address,
  /** Spec 408 §2.1 — the delegates this session key may present the principal's delegations to. */
  presentsTo: readonly Address[],
  validitySeconds = PERSON_INTERACTIONS_SESSION_LEAF_TTL_SECONDS,
): { delegation: Delegation; digest: Hex } {
  const { leaf, digest } = buildSessionDelegation({
    delegator: personAgent,
    sessionKeyAddress,
    presentsTo,
    validUntil: Math.floor(Date.now() / 1000) + validitySeconds,
    enforcers: { timestamp: CONTRACTS.timestampEnforcer, value: CONTRACTS.valueEnforcer },
    chainId: CHAIN_ID,
    delegationManager: CONTRACTS.delegationManager,
  });
  leaf.signature = APPROVED_HASH_SENTINEL; // validated via the SA's approved-hash ERC-1271 branch (same as site)
  return { delegation: leaf, digest };
}
