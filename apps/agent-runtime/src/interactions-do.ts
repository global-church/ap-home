// InteractionsDO — the per-principal SERIALIZED execution point for the interaction substrate
// (spec 322 W2; the embryo of spec 316's PrincipalGatewayDO). One instance per principal SA
// (idFromName = lowercase org/person SA): every board/directory mutation for that principal flows
// through THIS object, giving the single-writer ordering the vault's last-writer-wins storage
// cannot (spec 322 §5). Plane-B custody: the DO stores the principal's steward-signed interactions
// grant (the OPERATIONAL wire lives with its delegate service — spec 322 §2); callers never touch
// `/mcp/vault/*` for interaction records.
//
// Gates (spec 322 §4), all fail-closed:
//   caller    = a broker-verified Home session (any principal kind) → the session SA;
//   member    = a CURRENT directory listing whose ERC-1271 proof re-verifies AT GATE TIME against
//               the subject SA (index presence is never trust — the index is writable under the
//               execution grant);
//   steward   = a PRESENTED org→person stewardship DelegationWire, signature-verified against the
//               org (approved-hash 0x03 wires validate through the SA's ERC-1271 branch) and
//               checked unrevoked on-chain;
//   replay    = monotonic publishedAt per subject + tombstones honored by the gate.
// The VAULT enforces scopes only — never membership (stated so nobody optimizes this gate away).
// Audit: D1 (spec 322 §7), before commit.
import { CONTACT_FIELD_ARGS, contactField, precisionOf } from '@agenticprimitives/ontology';
import { createPublicClient, http, decodeAbiParameters, type Address, type Hex } from 'viem';
import { chainFor } from './chain';
import { kinTermFor, householdRoleFor } from '@agenticprimitives/ontology';
import { hashDelegation, decodeTimestampTerms, decodeVaultRecordScopeTerms, vaultRecordScopeAllows, VAULT_RECORD_SCOPE_ENFORCER, SESSION_AUDIENCE_ENFORCER, decodeSessionAudienceTerms, type Delegation, type VaultRecordScopeGrant, currentWireOf, LINEAGE_RECORD_PREFIX, type DelegationLineageV1 } from '@agenticprimitives/delegation';
import { PrincipalGatewayDO } from '@agenticprimitives/fabric/cloudflare';
import { governorOf, WORKSPACE_GOVERNOR_RECORD } from '@agenticprimitives/context';
import { buildMountedGatewayDeps } from './gateway-mount.js';
import { loadPlaybook, countedOp, countVaultCall } from '@agenticprimitives/harness';
import { classifyDivergence, recordDivergence, shouldShadow, SHADOW_INTERVAL_MS, type Divergence } from '@agenticprimitives/fabric';
import { gatewayStage, GATEWAY_ADOPTION } from './gateway-adoption.js';
import { verifyDelegationWire, type DelegationWireLike } from '@agenticprimitives/a2a';
import { enforcersFromEnv } from './org-wire.js';
import { parseRoleOffer, resolveAssignedRole, roleFieldsFromOffer, withoutRoleFields, offerFromRoleFields, PLAIN_MEMBER, type AssignedRoleFields } from './org-role.js';
import { A2A_ANY_SKILL, decodeAllowedMethodsTerms, decodeAllowedTargetsTerms, skillSelector } from '@agenticprimitives/a2a';
import {
  appendBoardPost,
  assistantTrigger,
  buildAssistantInboxReply,
  buildOutboundMessage,
  createBoardChannel,
  directConversationId,
  canSeeChannel,
  interactionViewOfChannel,
  channelParticipationPolicy,
  canonicalizeMessage,
  createVaultMessageBodyStore,
  fixedWindowAllow,
  inboxAssistantTrigger,
  isListingCurrent,
  isRetryableVaultToolFailure,
  setTopicAssistant,
  setTopicRouting,
  sha256Hex32,
  validateDirectoryListing,
  CONSULT_SKILL_ID,
  ROUTED_CONSULTATION_CONTEXT_KIND,
  ROUTING_FANOUT_DEFAULT,
  consultGrantRecordKey,
  eligibleConsultMembers,
  verifiedBodiesFromBatch,
  type ChannelMessageEntryV1,
  type ChannelV1,
  type ConsultProvenanceV1,
  type ConsultRosterRowV1,
  type ContextRefV1,
  type ConversationDescriptorV1,
  type DirectoryListingV1,
  type FixedWindowState,
  type MessageEnvelopeV1,
  type AnyMessageEnvelope,
  type MessageEventV1,
  type PersonAssistantV1,
  type TopicAssistantV1,
} from '@agenticprimitives/fabric/messaging';
// spec 341 Wave 2a — the inbox read cursor (Ring-0, pure; survives the Wave 5 transport change).
import { inboxRevision, upsertConversation, type InboxDataV1 } from '@agenticprimitives/fabric';
import { generateMessageId, messageBodyResource, type MessageEnvelopeV2 } from '@agenticprimitives/fabric/messaging';
import { mentionsIn, resolveMentions, topicThreadId, topicContextRef } from './mentions.js';
import { emptyIndex, indexDoc, searchIndex, SEARCH_INDEX_KEY, type SearchDocV1, type SearchIndexV1 } from './work-search.js';
// spec 341 §5.1b — outbound delivery, performed here because this is where the signing key is.
import { deliverOutbound, wireTargets } from './outbound-delivery.js';
import { messagingScopeCovers, messagingScopeDepsFromEnv } from './messaging-scope.js';
import { wrapSessionSignature } from '@agenticprimitives/a2a';
// spec 341 §7 — the in-Worker marker, split off the custody secret.
import { internalHeaders, internalMarker, isInternalCall } from './internal-marker.js';
import { PAIRING_KEY, PAIRING_INDEX_KEY, PAIRING_TTL_MS, PAIRING_CAP, mintCode, parsePairingOptions, claim as pairingClaim, complete as pairingComplete, take as pairingTake, isExpired as pairingExpired, type PairingStateV1 } from './runtime-pairing.js';
import { parseRuntimeHost, RUNTIME_HOST_KEY, RUNTIME_WAKES_KEY, RUNTIME_WAKE_PREFIX, RUNTIME_WAKES_CAP, type WakeReceiptV1 } from './runtime-wake.js';
import type { A2aTransport } from '@agenticprimitives/a2a';
import { AgentNamingClient } from '@agenticprimitives/agent-naming';
import type { Vault } from '@agenticprimitives/vault';

import { caip10, verifyHomeSession, verifyRelyingIdToken } from './custody-oidc.js';
import { verifyBridgeCall, nonceStoreFromKv, type NonceStore } from './bridge-hmac';
// Hoisted-function import from index.js — the documented safe cycle (see a2a-task-do.ts:38).
import { buildAuditSink, callMcpToolBound, interactionsSessionAccount, interactionsSessionKeyConfigured, fireEndeavorEventTriggers, afterEndeavorCommit, type Env, type IncomingDelegation } from './index.js';
import { checkSessionWireShape } from '@agenticprimitives/a2a';
import { handleEndeavorOp, reduceEventLog, coordinationEventsResource, COORDINATION_REQUESTS_RESOURCE, type CoordinationRequestsDocV1, type EndeavorOpDeps } from './endeavors.js';
import type { CoordinationEventV1 } from '@agenticprimitives/coordination';
import { ERC1271_MAGIC_VALUE as ERC1271_MAGIC } from '@agenticprimitives/types';
import { vaultServerId } from './vault-server-id.js';
import { DIRECTORY_OPS, handleDirectoryOp, type DirectoryCtx, type Wire as DirectoryWire } from './operator-directory-ops.js';
import { makeSealer, SEAL_PURPOSE, type Sealer, type StoredDek } from './directory-seal.js';
import { RemoteAgenticKmsProvider } from '@agenticprimitives/key-custody/agentic';
import { agenticKmsConfig } from './akcs.js';

const ERC1271_ABI = [{ type: 'function', name: 'isValidSignature', stateMutability: 'view', inputs: [{ name: 'hash', type: 'bytes32' }, { name: 'signature', type: 'bytes' }], outputs: [{ type: 'bytes4' }] }] as const;
const IS_REVOKED_ABI = [{ type: 'function', name: 'isRevoked', stateMutability: 'view', inputs: [{ name: 'delegationHash', type: 'bytes32' }], outputs: [{ name: 'revoked', type: 'bool' }] }] as const;

// spec 324 §10 conversation/topic split (renamed from board.* in the W6 key migration): descriptors in
// `conversation.index`; per-topic message projections in `conversation.topic:<id>` (multi-writer conflicts
// shrink to same-topic; reads stop paying for the whole board; per-topic scopes become possible). NO dual-read
// from the old `board.*` keys (ADR-0013) — the scope rename forces a grant re-enable, which self-invalidates.
const CONVERSATION_INDEX_RESOURCE = 'conversation.index';
const TOPIC_RESOURCE = (conversationId: string): string => `conversation.topic:${conversationId}`;
const DIRECTORY_RESOURCE = 'directory.data';
// Org-local display names for members who have not published a signed listing.
// Rides `vault:org.membership:*` so existing interactions grants stay current.
const LOCAL_NAMES_RESOURCE = 'org.membership:local-names';

// Topic participation (tbox/messaging.ttl §Topic participation). RESTRICTED topics ASSERT participation:
// apmsg:DiscussionInvitation rows live in `conversation.topic:invitations`; accepted participations
// (apmsg:DiscussionParticipation situation projections) in `conversation.topic:participation:<topicId>`.
// Both deliberately ride the EXISTING `vault:conversation.topic:*` grant scope (anchored prefix match) so
// no grant re-enable is needed; topic ids are generated `conv_*` so the sub-keys can't collide. OPEN topics
// NEVER touch these records — participation there is DERIVED from org membership (the directory-listing
// gate) at read time and MUST NOT be asserted (same doctrine as aporg:memberOf).
const DISCUSSION_INVITATIONS_RESOURCE = 'conversation.topic:invitations';
const TOPIC_PARTICIPATION_RESOURCE = (topicId: string): string => `conversation.topic:participation:${topicId}`;

// spec 327 §4b — the org's ASSISTANT PLAYBOOK: a steward-authored Agent Skill package (SKILL.md
// projection, ADR-0051 vocabulary) whose markdown becomes the LLM planner's system prompt for the
// discussion turn. ONE org-level doc, deliberately keyed under the `conversation.topic:` namespace
// so it rides the EXISTING `vault:conversation.topic:*` grant scope (the invitations/participation
// carve) — no grant re-enable. Steward-gated authoring; the harness reads it marker-gated.
const ASSISTANT_SKILL_RESOURCE = 'conversation.topic:assistant-skill';
// Product cap on the assistant-skill playbook markdown (stored as a vault record). Not a
// storage/KEK limit — vault records hold much larger JSON; the only cost is LLM context per
// turn, so this is set generously to allow rich, multi-skill, vault-leveraging playbooks.
const ASSISTANT_SKILL_MAX_CHARS = 65536;
interface AssistantSkillDocV1 { version: 'ap.assistant-skill.v1'; markdown: string; updatedBy: string; updatedAt: string }

// spec 327 — org-assistant dispatch bounds. Per-topic fixed window in DO storage: member-driven
// mention storms are bounded; drops are audited (`interactions.assistant.rateLimited`), never queued.
const ASSISTANT_RATE_KEY = (topicId: string): string => `assistant.rate:${topicId}`;
const ASSISTANT_RATE_WINDOW_MS_DEFAULT = 10 * 60_000;
const ASSISTANT_RATE_MAX_DEFAULT = 6;
/** The bound is DEPLOY CONFIG, not a constant (ADR-0013 — a config choice, not a second mechanism).
 *  The defaults are the shipping values; an env override exists because the limit is the difference
 *  between "bounded against a mention storm" and "cannot be exercised", and an app integrating
 *  against this plane hits the second long before a room full of people hits the first. A dropped
 *  turn is silent to the poster BY DESIGN (audited, never queued), so a limit tuned for production
 *  reads exactly like a broken assistant to whoever is building against it. */
const rateBound = (env: Record<string, unknown>): { windowMs: number; max: number } => {
  const n = (v: unknown, d: number): number => {
    const x = Number(v);
    return Number.isFinite(x) && x > 0 ? x : d;
  };
  return {
    windowMs: n(env.ASSISTANT_RATE_WINDOW_MS, ASSISTANT_RATE_WINDOW_MS_DEFAULT),
    max: n(env.ASSISTANT_RATE_MAX, ASSISTANT_RATE_MAX_DEFAULT),
  };
};
/** Context bound for the assistant's topic reads (spec 327 §4). */
const ASSISTANT_READ_LIMIT = 20;
const ASSISTANT_BODY_CLIP = 2000;

// ── spec 328 — the PERSON inbox auto-reply assistant (the person twin of spec 327). ──
// Config is a VAULT record, deliberately keyed under `conversation.topic:` so it rides the EXISTING
// `vault:conversation.topic:*` grant scope (the 327 §4b carve) — no grant re-enable. The person's
// PLAYBOOK is not a second record here: it is the compiled archetype (`archetype.assignment`, spec 354),
// read through `loadPlaybook` by the inbox/consult turns.
const PERSON_ASSISTANT_RESOURCE = 'conversation.topic:person-assistant';
/** DO-storage gate flag — a CACHE of the canonical vault record's `enabled`, maintained ONLY by
 *  the enable/disable ops (single writer), so disabled inboxes exit every scan in O(1) with no
 *  vault read. The canonical record is re-read before any dispatch AND at the write (§5). */
const INBOX_ASSISTANT_FLAG_KEY = 'assistant.inbox.on';
/** Seen ledger — envelope ids already scanned (bounded ring). Both commit paths (internal.deliver
 *  and the Home's whole-doc inbox.put) diff against it; first sight SEEDS without dispatching so
 *  history/replays never trigger. */
const INBOX_ASSISTANT_SEEN_KEY = 'assistant.inbox.seen';
const INBOX_ASSISTANT_SEEN_CAP = 300;

// ── spec 334 §6 auto-work — "the agent does the work it can". A single per-principal switch (org OR
// person) that turns the plan-draft turn into a full autopilot: draft → adopt → execute every step it
// can do itself → satisfy. Config is a VAULT record under `conversation.topic:` (rides the existing
// 327 §4b grant scope — no re-enable); the DO flag is the O(1) gate cache the trigger paths read.
const AUTO_WORK_RESOURCE = 'conversation.topic:auto-work';
const AUTO_WORK_FLAG_KEY = 'assistant.autowork.on';
/** A HOST org's archetype dispatch grant, held by the CALLING org's DO and keyed by the host.
 *  Mirrors `consultGrantRecordKey` one relationship over: the sender caches the recipient's opt-in
 *  and re-reads it per send, so an on-chain revocation stops the next dispatch rather than the one
 *  after the cache expires. */
const archetypeGrantRecordKey = (hostSA: string): string => `archetype.grant:${hostSA.toLowerCase()}`;

/** The coordination log stores short results INLINE as `urn:ap:evidence:<text>` /
 *  `urn:ap:outcome:<text>` refs — so a step's deliverable and an endeavor's closing note are already
 *  in the log, not behind a vault read. Decoding them is what turns "which steps are done" into the
 *  WORK ITSELF, which is the whole reason a requester follows an intent it dispatched. */
function decodeInlineRef(iri: string | undefined): string | null {
  if (!iri) return null;
  for (const prefix of ['urn:ap:evidence:', 'urn:ap:outcome:']) {
    if (iri.startsWith(prefix)) {
      try { return decodeURIComponent(iri.slice(prefix.length)); } catch { return null; }
    }
  }
  return null;
}

/** Bound autopilot dispatches per endeavor per window — one flight at a time; re-triggers are
 *  idempotent (the pipeline skips already-satisfied steps), this just avoids stampedes. */
const AUTO_WORK_RATE_KEY = (endeavorId: string): string => `assistant.rate:autowork:${endeavorId}`;
interface AutoWorkV1 { version: 'ap.auto-work.v1'; enabled: boolean; enabledBy: string; enabledAt: string }
const INBOX_ASSISTANT_RATE_KEY = (conversationId: string): string => `assistant.rate:inbox:${conversationId}`;
/** Bound dispatches per scan — a whole-doc put can carry several new envelopes at once. */
const INBOX_ASSISTANT_MAX_PER_SCAN = 2;
/** Context bound for the assistant's conversation reads (spec 328 §4). */
const INBOX_ASSISTANT_READ_LIMIT = 8;

// spec 329 §3.1 — the DO-custodied ORG consult wire (the routing-enable ceremony's mint): a narrow
// org-signed delegation (delegator = this org, delegate = the interactions-session KMS key,
// allowedMethods = [discussion.consult selector]) that lets the org's runtime SIGN consult-rail
// message/send + tasks/get digests as the org. A stored wire lives with its delegate service
// (spec 322 §2); the KMS key itself never rests here. Clearing this key is the org-side routing
// kill switch (the on-chain revocation is the authority kill at every member's gate).
const ROUTING_ORG_WIRE_KEY = 'routing.orgWire';
interface RoutingOrgWireRecord { wire: IncomingDelegation; hash: string; sessionKey: string; enabledBy: string; enabledAt: string }

// spec 341 §5.1b — the DO-custodied PERSON MESSAGING wire. Same shape and same reason as the org
// consult wire above, for the other direction of the same problem: the Home is this person's control
// plane but holds no key, so it cannot sign a message as them. The wire (delegator = this person,
// delegate = the interactions-session KMS key, allowedMethods = the messaging.deliver selector,
// allowedTargets = the counterparties it covers) lets THIS runtime sign outbound delivery as them.
//
// IT IS CUSTODIED HERE, NOT AT THE HOME, for the reason a wire always lives with the runtime that
// spends it: an artifact stored where it cannot be used is a copy, and a second copy is a second
// thing to revoke. Clearing this key is the person-side send kill switch; the on-chain revocation is
// the authority kill at every recipient's gate.
// spec 341 §4.3 — PER-APP READ GRANTS. One scoped delegation per relying app, keyed by the app's
// VERIFIED `aud`, so a person can revoke ONE app's read access without disturbing anyone else.
//
// WHAT THIS BUYS, precisely: before it, every caller reached the person's records through `st0.grant` —
// one broad grant shared by the Home and every relying app. Revoking an app meant revoking its OIDC
// client registration, which is a registry edit at one server, not an authority change; other Homes and
// other copies of the token kept working. A per-app delegation is revocable ON-CHAIN, and the
// revocation is visible to everyone who checks rather than to whoever happens to read that registry.
//
// The delegate stays the interactions service SA — the same party that performs the vault call either
// way. What differs per app is WHICH delegation authorizes it, and therefore what a revocation kills.
/**
 * The vault resource each owner-facing op touches.
 *
 * Kept as data rather than inlined per op so adding an op to the per-app rail is one row, and so the
 * set an app must be granted is READABLE — a person approving an app should be able to see what it can
 * reach without tracing call sites. An op absent from this map is not scope-checked here; demo-mcp
 * still enforces, so the failure is a worse error message, never a wider grant.
 */
const OP_RESOURCE: Record<string, string | undefined> = {
  'inbox.get': 'vault:inbox.data',
  'inbox.put': 'vault:inbox.data',
  // The SAME resource as `inbox.get`, because it is the same read served by the other plane. A mounted
  // op that needed a wider scope than the one it mirrors would not be a migration step, it would be a
  // new capability wearing one as a disguise.
  'gateway.inbox.get': 'vault:inbox.data',
  'inbox.body.get': 'vault:message.body:dm:',
  'dm.body.put': 'vault:message.body:dm:',
  'controlevents.append': 'vault:control-events.data',
};

/**
 * Which scoped-grant question a content op asks, or none.
 *
 * `content.put` with `data: null` is how a DELETE arrives (demo-sso-next `library.ts` `delRecord`),
 * so it asks for `delete` — a grant saying `ops: ['write']` must not erase records.
 *
 * `content.catalog` returns undefined for WRITES: the index lists every artifact in the org, so
 * rewriting it under a scope that names one community could silently drop another's. Reading it is
 * allowed to be scoped, which is itself a limit worth naming — the catalog is an aggregate, so a
 * scope covering it discloses the whole index and cannot be narrowed further until the catalog is
 * split per family.
 */
function scopedContentOp(
  op: string,
  resource: string,
  data: unknown,
): { resource: string; op: 'read' | 'write' | 'delete' } | undefined {
  if (op === 'content.get') return { resource, op: 'read' };
  if (op !== 'content.put') return undefined;
  if (resource.startsWith('content.artifact.')) return { resource, op: data === null ? 'delete' : 'write' };
  // THE CATALOG, FOR A SCOPED WRITER, IS A MERGE — NEVER A REPLACEMENT. `content.catalog` is the org-wide
  // index and every save rewrites it (demo-sso-next `library.ts` puts the list before the artifact), so a
  // grant that can write a record but not the catalog can write nothing at all — which is what every
  // scoped role wire hit (2026-09-28: `unauthorized … resource content.catalog`). Admitting the write here
  // asks the wire the honest question (does it name `vault:content.catalog` with `write`?), and the
  // content handler then MERGES: entries the grant covers are taken from the submission, every other
  // entry is kept as stored. A scoped caller still cannot drop another family's records, and a null
  // (delete) or non-list catalog is refused before the wire is consulted.
  if (resource === 'content.catalog' && Array.isArray(data)) return { resource, op: 'write' };
  return undefined;
}

const READ_GRANT_KEY = (clientId: string): string => `read.grant:${clientId.toLowerCase()}`;
/** A STUDY GRANT — the person's delegation to a COACH SERVICE (never an app, never a person) to read their
 *  card-room study records and append the coach's notes. Keyed by the coach's typed name. */
const STUDY_GRANT_KEY = (coach: string): string => `study.grant:${coach.toLowerCase()}`;
interface StudyGrantRecord { wire: IncomingDelegation; hash: string; coach: string; delegate: string; resources: string[]; storedAt: string }
interface ReadGrantRecord { wire: IncomingDelegation; hash: string; clientId: string; storedAt: string }
/** Spec 400 W2a/B4 — a STANDING GRANT this agent's custodian issued to its runtime's key (the open mandate), kept
 *  here like a read grant so the grants screen lists it and a revocation can expand its digest back into the struct. */
const STANDING_GRANT_KEY = (ref: string): string => `standing.grant:${ref.toLowerCase()}`;
interface StandingGrantRecord { wire: IncomingDelegation; hash: string; capabilities: string[]; locations: string[]; holder: string; holderName?: string; validUntil: number; storedAt: string }

const MESSAGING_WIRE_KEY = 'messaging.wire';
// Spec 410 §3 — THE OPERATION LEDGER: `op:<operationId>` → what this object did for that logical operation (a send's
// envelope id, a write's record type). A serving-plane pointer, rebuildable from the vault and the threads (ADR-0055);
// what it buys is the reconcile: a retry after a lost response finds the operation here and does not act twice.
const OP_LEDGER_KEY = (operationId: string): string => `op:${operationId}`;
interface OpLedgerRecord { kind: 'send' | 'write'; ref: string; at: string }
/** How long the ledger answers for an operation. A retry later than this finds ABSENT and may act again — said on
 *  every lookup (`retentionDays`) so a caller can tell "never happened" from "too old to know". Rows past it are
 *  swept lazily: a bounded page on each write, and any expired row a lookup lands on. */
export const OP_LEDGER_RETENTION_DAYS = 30;
const OP_LEDGER_SWEEP_PAGE = 64;
const opLedgerExpired = (rec: OpLedgerRecord, now: number): boolean => now - Date.parse(rec.at) > OP_LEDGER_RETENTION_DAYS * 86_400_000;
/** TWO artifacts, because the gate asks two questions. `wire` (person → session key) authorizes the key
 *  to produce signatures that count as the person's, and travels INSIDE each signature. `transport`
 *  (person → person) authorizes the skill against the named recipients, and is what
 *  `authorizeA2aMessage` reads. See `outbound-delivery.ts` for why one cannot serve both. */
interface MessagingWireRecord {
  wire: IncomingDelegation;
  transport: IncomingDelegation;
  hash: string;
  transportHash: string;
  sessionKey: string;
  enabledAt: string;
}
/** The one skill an outbound 1:1 message uses. The wire must name its selector, and the shape check
 *  pins it — a wire minted for this rail must not authorize another. */
const MESSAGING_DELIVER_SKILL = 'messaging.deliver';

/** The scope set the CURRENT wave requires — a stored grant missing any of these is STALE and the
 *  steward re-signs via the Enable ceremony (grant re-signs are ceremonies, not migration). */
// NOTE: `vault:org.applications` is deliberately NOT here. It ships in the interactions grant (so fresh grants
// can write the applications doc), but it is a FEATURE-specific additive scope — gating the WHOLE interactions
// plane (channels/directory/inbox/invite) on it would strand any grant that predates it (or was signed in a
// deploy window) with a blanket "stale — re-enable". A grant lacking it simply can't write org.applications
// (the vault-record-scope caveat enforces that at the vault); everything else keeps working.
// Same precedent for the spec-334 coordination docs (`vault:coordination.requests`, `vault:coordination.index`,
// `vault:coordination.endeavor:*`): additive scopes the grant-signing ceremony (demo-sso-next) must include for
// endeavor.* ops to reach the vault — a grant lacking them is denied per-record at demo-mcp, never blanket-staled.
// `vault:content.*` (ADR-0055, #489) belongs to that same class and was listed here by mistake: it stranded
// EVERY grant signed before 2026-07-26 with a blanket stale-409 across the whole interactions plane — channels,
// directory, inbox, the assistant playbook — for want of a scope only the content.* ops use. Those ops already
// fail closed on their own (`no delivery grant`, 409), and the vault-record-scope caveat denies an out-of-scope
// content write at demo-mcp. Removing it restores exactly the behaviour the two paragraphs above describe.
export const REQUIRED_SCOPES = ['vault:conversation.index', 'vault:conversation.topic:*', 'vault:message.body:topic:*', 'vault:inbox.data', 'vault:directory.data', 'vault:relationships.data', 'vault:member.profile:*', 'vault:org.membership:*', 'vault:message.body:dm:*', 'vault:impact-profile', 'vault:skills.data', 'vault:home.manifest', 'vault:control-events.data'] as const;

// Spec 363 W4 — the household record is ADDITIVE, deliberately NOT in REQUIRED_SCOPES. Adding a resource
// there marks every grant in the estate stale at once (`grantIsCurrent`), which asks every person to
// re-sign for a record most of them will never write. New grants carry it (genesis + the Home's list);
// an older grant refuses the write with `record_scope_denied` and the Home offers Enable — which is the
// same shape `vault:archetype.assignment` already uses, and for the same reason.

// spec 338 §7 — the resolution records are ISSUED (see the Home's interactions struct) but deliberately
// NOT REQUIRED here. This set is the STALENESS GATE: adding to it declares every existing grant
// insufficient, and a person whose grant is stale can do nothing at all until they re-sign. That is the
// right trade for a record family everyone needs and the wrong one for a new capability few have used —
// it took the whole estate offline with 409s the moment it shipped. So a grant issued before this feature
// keeps working for everything it already did, and cannot write a resolution record until it is re-issued,
// which is exactly what the requester is told.

// 1-1 inbox residency (spec 322 W3f): the DELIVERY grant is WRITE-ONLY — every inbox.data READ and
// dm-body READ rides the interactions grant THROUGH this DO (single writer, single reader path).
const INBOX_RESOURCE = 'inbox.data';
/** The token handed to the mounted gateway's cold path. The gateway is constructed around ONE grant, so
 *  there is no second delegation this could select and nothing for it to carry — it exists because
 *  `verifyToken(token)` is the gateway's cold-path shape, and naming it is better than passing `''`. */
const GATEWAY_GRANT_TOKEN = 'mounted:grant';
const DM_BODY_PREFIX = 'message.body:dm:';
// spec 324 §7 Tier-2 — the org's pending MembershipApplications doc, a plain whole-doc record in the org's
// vault (NOT the inbox — a non-member's application must surface reliably to the steward). Bridge-only: the
// Home appends on the applicant's behalf (applying is open) and reads on the steward's behalf.
const APPLICATIONS_RESOURCE = 'org.applications';

// Person-plane records (spec 322 W3d): the person's authoritative org-relationship doc and their
// per-org shareable profile cards. Self-gated ops only — the session SA must BE the principal.
const RELATIONSHIPS_RESOURCE = 'relationships.data';
const MEMBER_PROFILE_RESOURCE = (org: string): string => `member.profile:${org.toLowerCase()}`;

// spec 324 W3 — the AUTHORITATIVE OrganizationMembership record (a private SituationV2 + its credential),
// per org, in the party's own vault. Membership is NOT a delegation and NOT a directory listing (ADR-0048
// #3/#6): this record is the single source of truth; the related:* link, directory roster row, and gate
// caches are provenance-tagged projections of it. Self-gated writes (the principal owns their membership
// record); the org retains its own copy in the org's DO.
const MEMBERSHIP_RESOURCE = (org: string): string => `org.membership:${org.toLowerCase()}`;
/** spec 338 §7 — requests for a way to reach an unlisted agent, in the OWNER's own vault. */
const RESOLUTION_REQUESTS_RESOURCE = 'resolution.requests';
/** spec 338 §7 — the grants a person HOLDS: permission to discover, never to use. */
const RESOLUTION_GRANTS_RESOURCE = 'resolution.grants';

// spec 323 W2 — owner-own capability DOCUMENTS (last-writer-wins whole-doc records), reachable ONLY
// self (session SA === principal) over the interactions grant. This is the delegation-authorized,
// KEK-encrypted replacement for the bearer/service-MAC `impact-profile` path (V-1 remediation) and
// the app-local `skills`/`home-manifest` KV. NOT append logs (control-events needs its own op).
// `capabilities.data` is the CURRENT key (ADR-0051 renamed it); `skills.data` is the same record under
// its old name, kept so an unmigrated one still reads and writes. The rename landed on the Home's write
// path without landing here, so every capability save was refused by this allowlist and fell back to the
// Home's KV cache — the save LOOKED fine and nothing reached the owner's vault. A best-effort mirror
// hides a missing allowlist entry perfectly; only reading the vault back shows it.
/** spec 360 — the ONLY record families an internal declared-effect write may deposit in a vault it does
 *  not own. A prefix list, not a wildcard: this op's whole safety is that it cannot be pointed anywhere. */
// Spec 370 P7 — the person's own conversation memory rides the same in-Worker door: their agent, writing
// what it resolved for them into their own vault. Memory, never a general write path.
// Spec 385 — the scoped confirmation memory is the same kind of thing: the person's agent writing what THEY
// chose into their own vault, from the resume that supplied the choice; and clearing it when they say so.
// Spec 402 W1 — `memory.facts` is what the person's agent remembers about THEM: their own words, kept from their own
// ask (remember / forget), the same door as a standing instruction.
// Spec 401 — a CONTACT (`contact:<sa>`) is the person's own record of who they let in, written by their agent under
// their own signed mandate (the act that mints the grant) into their own vault. Its own family: an organization's
// invitation key stays a delivery-plane write (the fabric firewall), untouched by this door.
const EFFECT_WRITABLE_RECORDS = ['payment.receipt:', 'conversation.recent', 'run.provenance:', 'run.artifact:', 'run.anchor:', 'run.measures:', 'build.run:', 'build.promotion:', 'connector.mcp:', 'agent.budget', 'confirmation.preferences', 'standing.instructions', 'memory.facts', 'routines.data', 'person.preferences', 'playbook.memory:', 'cardroom.', 'contact:', 'delegation.lineage:', 'relationships.credential:', 'relationships.revocation:', 'interaction.dispute:', 'run.dispute:', 'content.catalog', 'content.artifact.'] as const; // spec 412 W5 — the owner's Library, written by the owner's own agent (library.file.save / visibility / publish) // spec 410 §8 — each party's copy, in its own vault // spec 410 §1.2 — a wire re-issued for a rotation, in the delegator's own vault

const CAPABILITY_RECORDS = new Set(['impact-profile', 'capabilities.data', 'skills.data', 'home.manifest', 'control-events.data', 'archetype.assignment',
  // spec 422 §9.3 — the person's Security section: credential labels + the channels that open the home. Hers to write.
  'security.credentials', 'security.channels']);
const CONTROL_EVENTS_RESOURCE = 'control-events.data';
const CONTROL_EVENTS_CAP = 200; // ring buffer — the person's portable timeline is a recent-window projection.

// spec 323 §3: wires whose DELEGATE is this person (stewardship, member-access) are the person's
// own private credentials — they ride the entry so any Home can act from the vault (ADR-0025).
// spec 323 W1-tail — kind/parent capture the managed-tree SHAPE (org / org-treasury / person-treasury
// and where it hangs), so a second Home reconstructs the FULL tree + inbox-control from the vault, not
// just member/steward org links.
// spec 324 W3 — provenance fields (membershipId / membershipSituationHash / enrollmentDecisionRef) make this
// projection traceable back to its authoritative OrganizationMembership Situation. `relationship:'member'`
// here is a projection LABEL, never authority (ADR-0048 #3): the delegations it carries are the authority
// artifacts issued BECAUSE of membership; the membership itself is the SituationV2 the provenance points to.
interface RelationshipEntryV1 { org: string; relationship: 'member' | 'steward' | 'self'; orgName?: string; kind?: string; parent?: string; delegationHash?: string; delegations?: IncomingDelegation[]; membershipId?: string; membershipSituationHash?: string; enrollmentDecisionRef?: string; updatedAt: string }
interface RelationshipsDocV1 { orgs: Record<string, RelationshipEntryV1> }

// apmsg:DiscussionInvitation row (restricted topics only) — a directed proposal, NOT a participation;
// acceptance converts it into the participation row + members projection update.
interface DiscussionInvitationRowV1 { id: string; topicId: string; invitedAgent: string; invitedName?: string; invitedBy: string; invitedByName?: string; role: 'facilitator' | 'contributor'; status: 'invited' | 'accepted' | 'declined' | 'revoked'; createdAt: string; decidedAt?: string }
// apmsg:DiscussionParticipation projection row (restricted topics): personSA + discussion-scoped role +
// provenance back to the accepted invitation. The descriptor's `members[]` stays the fast-ACL projection
// of these rows (canSeeChannel); THIS doc is the situation-backed source.
interface DiscussionParticipationRowV1 { personSA: string; personName?: string; role: 'facilitator' | 'contributor'; situationRef: string; invitationRef: string; acceptedAt: string; status: 'active' | 'revoked'; revokedAt?: string }
/** Grants LEDGER row (spec 322 W3e §2): hash + metadata ONLY — the wire itself is a bearer secret. */
interface GrantLedgerRowV1 { hash: string; delegate: string; resources: string[]; storedAt: string }

interface IndexedListing { listing: DirectoryListingV1; label: string }
interface StoredState {
  grant?: IncomingDelegation;
  /** NEW-C1 — the PRINCIPAL-signed DEL-001 session-delegation leaf (principal → the interactions-session
   *  KMS key). Custodied at grant.put alongside `grant`. When present (+ GCP_KMS_INTERACTIONS_KEY_NAME set),
   *  vaultFor CLIENT-MINTS a bound token (callMcpToolBound) instead of server-mint — no DEMO_ALLOW_SERVER_MINT.
   *  Absent ⇒ vaultFor falls back to the server-mint bridge (existing principals migrate on next enable). */
  sessionLeaf?: IncomingDelegation;
  /** Spec 423 §2.1 route A — the PRE-APPROVED LEAF LADDER: N session leaves signed together at enable, windows
   *  tiling forward, so a live rung exists for N·T with no steward present to re-sign. When set it supersedes
   *  `sessionLeaf` (which stays the live-at-enable rung for back-compat readers). The DO picks the live rung
   *  (`activeLeaf`); when all rungs expire it is `needsReEnable`, same as a lapsed single leaf. */
  sessionLeaves?: IncomingDelegation[];
  /** spec 323 W3 — the WRITE-ONLY delivery wire (owner → DELIVERY_SERVICE_SA), custodied HERE (a
   *  stored wire is a bearer secret; the DO is the delegate-service side, spec 322 §2). The DO is
   *  now the sole holder+wielder for dm-body writes — no app (not even the Home) keeps it. */
  deliveryGrant?: IncomingDelegation;
  /** The OPERATOR DIRECTORY grant (operator org → the directory service), scoped exactly to `vault:contact:*`,
   *  `vault:directory.audit:*`, `vault:export:*`, read+write. Held only here; used only by operator-directory-ops.ts
   *  (2026-10-23, gc-estate/docs/operator-workspace.md). */
  directoryGrant?: IncomingDelegation;
  /** Issuance ledger (spec 322 W3e): every grant ever custodied here, hash/metadata only. */
  ledger?: GrantLedgerRowV1[];
  /** subject(lowercase caip10) → highest publishedAt accepted (replay guard) + tombstone flag. */
  subjects?: Record<string, { publishedAt: string; tombstoned?: boolean }>;
}

const json = (b: unknown, s = 200): Response => new Response(JSON.stringify(b), { status: s, headers: { 'content-type': 'application/json' } });

/**
 * THE COST OF AN OP, COUNTED — spec 396 (DO economics). Every vault call this object makes on behalf of one
 * request is counted in a request-scoped store (AsyncLocalStorage — concurrent requests never share a
 * counter) and reported on the response as headers: `x-ap-vault-calls`, `x-ap-vault-throttled`, `x-ap-ms`,
 * `x-ap-vault-tools` (tool=n,…). Numbers, never content. The organization's vault budget (120 verified calls a
 * minute) is the binding constraint the live gates keep hitting; a cost nobody can read is a cost nobody fixes.
 */
// The counter itself is `@agenticprimitives/harness` `op-cost.ts` (spec 399 §4 promotion): `countedOp` runs an op
// under a fresh counter, `countVaultCall` charges one tool call to it, and the headers are stamped on the way out.

/**
 * Injected external seams (mirrors `packages/fabric`'s `GatewayDeps`).
 *
 * The DO reaches four external systems to serve a board read — broker JWKS, GCP KMS, demo-mcp and a
 * chain RPC — and until now reached all of them through `this.env` and module imports. That made the
 * board ops untestable except by reconstructing production state through HTTP stubs, which tests the
 * stubs. These two seams are the ones that matter: everything else the DO does is pure or KV.
 *
 * PRODUCTION NEVER PASSES THIS. The Cloudflare binding constructs `new InteractionsDO(state, env)`,
 * so `deps` is `undefined` and both paths fall through to the real implementations. It is an
 * injection point, not a bypass — there is no env flag that reaches it, deliberately, because a
 * runtime switch here would be a way to disable ERC-1271 verification in production.
 */
export interface InteractionsDeps {
  /** ERC-1271 verification. Default: a chain read via `env.RPC_URL`. */
  erc1271?(account: Address, digest: Hex, signature: Hex): Promise<boolean>;
  /** One demo-mcp vault tool call. Default: bound-mint transport over `env.MCP_URL`. */
  vaultTool?(
    grant: IncomingDelegation,
    toolName: 'get_vault_record' | 'get_vault_records' | 'set_vault_record' | 'list_vault_record',
    toolArgs: Record<string, unknown>,
  ): Promise<Response>;
  /** Typed-name resolution for mentions (spec 400 W2). Default: the naming registry over `env.RPC_URL`. */
  resolveName?(name: string): Promise<Address | null>;
}

export class InteractionsDO {
  constructor(private state: DurableObjectState, private env: Env, private deps?: InteractionsDeps) {}

  /** ARCH-H1 — a per-instance RMW mutex. A Durable Object serves concurrent requests that interleave
   *  across the MCP round-trip, so two appends to the SAME doc both read rev N and one silently
   *  overwrites the other (lost update). This serializes read→modify→write for the ops that share a
   *  doc across DISTINCT writers — channel posts (many members), deliveries (many senders), timeline
   *  appends (many server flows). Reads never take it; self-only single-writer ops don't need it. */
  private mutating: Promise<unknown> = Promise.resolve();

  // VERIFY MEMO (perf, 2026-10-02). verifyWire does TWO on-chain RPC round-trips per read (an ERC-1271
  // isValidSignature and an isRevoked) and runs on EVERY authorized read — a single Home page load fans
  // out to many inbox/relationships/vault reads against the SAME standing wire, so the same two chain
  // reads ran dozens of times (the 7-25s reads). This memoizes a wire that was PROVEN VALID, keyed by
  // (expectedDelegator, expectedDelegate, signature), for a short TTL. It is NOT a fallback (ADR-0013):
  // the one mechanism — verifyDelegationWire — still decides; this only skips re-running it when it just
  // said yes. Only TRUE results are cached, so a failing verify is never locked in, and the TTL bounds
  // how long a revocation or a removed credential can go unnoticed. The DO instance is per-owner and
  // lives across requests, so the memo is warm for the burst that caused the problem.
  private static readonly VERIFY_MEMO_TTL_MS = 20_000;
  private static readonly VERIFY_MEMO_MAX = 256;
  private verifyMemo = new Map<string, number>(); // key → expiry epoch ms (only proven-valid wires)

  private serialize<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.mutating.then(fn, fn);
    this.mutating = run.then(() => undefined, () => undefined);
    return run;
  }


  private pub() {
    return createPublicClient({ chain: chainFor(this.env), transport: http(this.env.RPC_URL) });
  }

  /** spec 327 §3 — post-commit org-assistant dispatch. Fire-and-forget (the member's post already
   *  committed; a DO stays alive while work is pending): per-topic fixed-window rate limit, then an
   *  in-Worker call to the org's OWN A2aTaskDO (`/internal/discussion-respond`, the 318 §8.1
   *  intent-native gateway) carrying the ARCH-H2 internal marker. Every drop/failure is AUDITED and
   *  DROPPED — no retry into another mechanism (ADR-0013), no queue, no effect on the human post. */
  private dispatchAssistant(opts: { entry: ChannelV1; channelId: string; principal: string; triggerAuthor: string; triggerAuthorSa?: string; triggerBody: string }): void {
    const assistant = opts.entry.assistant;
    // The in-Worker marker, not the custody secret: this dispatch is a DO↔DO call (spec 341 §7).
    if (!assistant || !internalMarker(this.env)) return;
    const audit = buildAuditSink(this.env);
    void (async () => {
      const key = ASSISTANT_RATE_KEY(opts.channelId);
      const now = Date.now();
      const rate = ((await this.state.storage.get(key)) ?? { windowStart: now, count: 0 }) as { windowStart: number; count: number };
      const bound = rateBound(this.env as unknown as Record<string, unknown>);
      const inWindow = now - rate.windowStart < bound.windowMs;
      if (inWindow && rate.count >= bound.max) {
        await audit.write({ id: crypto.randomUUID(), timestamp: new Date().toISOString(), action: 'interactions.assistant.rateLimited', outcome: 'denied', actor: { type: 'service', id: opts.principal }, subject: { type: 'channel', id: opts.channelId } });
        return;
      }
      await this.state.storage.put(key, inWindow ? { windowStart: rate.windowStart, count: rate.count + 1 } : { windowStart: now, count: 1 });
      const stub = this.env.A2A_TASKS.get(this.env.A2A_TASKS.idFromName(opts.principal));
      const resp = await stub.fetch(new Request(`https://do/internal/discussion-respond?agent=${opts.principal}`, {
        method: 'POST',
        headers: internalHeaders(this.env),
        body: JSON.stringify({
          principal: opts.principal, channelId: opts.channelId, topicTitle: opts.entry.title,
          trigger: assistant.trigger, displayName: assistant.displayName, mentionHandle: assistant.mentionHandle,
          triggerAuthor: opts.triggerAuthor, ...(opts.triggerAuthorSa ? { triggerAuthorSa: opts.triggerAuthorSa } : {}), triggerBody: opts.triggerBody,
        }),
      }));
      const out = (await resp.json().catch(() => ({}))) as { ok?: boolean; error?: string };
      if (!resp.ok || out.ok === false) throw new Error(out.error ?? `assistant respond failed (${resp.status})`);
      await audit.write({ id: crypto.randomUUID(), timestamp: new Date().toISOString(), action: 'interactions.assistant.dispatch', outcome: 'success', actor: { type: 'service', id: opts.principal }, subject: { type: 'channel', id: opts.channelId } });
    })().catch((e) => {
      void audit.write({ id: crypto.randomUUID(), timestamp: new Date().toISOString(), action: 'interactions.assistant.dispatchFailed', outcome: 'error', actor: { type: 'service', id: opts.principal }, subject: { type: 'channel', id: opts.channelId }, reason: e instanceof Error ? e.message : String(e) }).catch(() => undefined);
    });
  }

  /** Spec 400 W2 (B5) — one document into this object's search index (DO-local, rebuildable). Never fails the write it
   *  follows: an index that could not be updated is rebuilt by `search.reindex`, and says nothing to the caller. */
  private async indexForSearch(id: string, doc: SearchDocV1, text: string): Promise<void> {
    try {
      const idx = ((await this.state.storage.get(SEARCH_INDEX_KEY)) as SearchIndexV1 | undefined) ?? emptyIndex();
      await this.state.storage.put(SEARCH_INDEX_KEY, indexDoc(idx, id, doc, text));
    } catch (e) { console.warn('[search] index write skipped:', e instanceof Error ? e.message : String(e)); }
  }

  /** Spec 400 W2 (B3) — MENTIONS INTO WORK. `@goose-2` in a topic: the mentioned MEMBER agent (any member, not only
   *  the org's own assistant) is handed the post as a message on the topic's thread — admitted by ITS OWN object
   *  (`/internal/admit-message` on its task DO: body, inbox, then its `message` triggers with profile `mention` and its
   *  runtime wake). The org resolves `@label` to a typed name and checks the member's invitation record in its own
   *  vault; a handle that names no member tells nobody. Post-commit, fire-and-forget: a failed hand-off is audited
   *  and dropped (ADR-0013), never queued, never affecting the poster's response. A mention grants nothing. */
  private dispatchMentions(opts: { entry: ChannelV1; channelId: string; principal: string; grant: IncomingDelegation; posterCaip: string; posterName: string; bodyText: string; messageId: string }): void {
    const refs = mentionsIn(opts.bodyText);
    if (!refs.length || !internalMarker(this.env)) return;
    const injected = this.deps?.resolveName;
    if (!injected && (!this.env.RPC_URL || !this.env.AGENT_NAME_REGISTRY || !this.env.AGENT_NAME_UNIVERSAL_RESOLVER)) return;
    const audit = buildAuditSink(this.env);
    const chainId = Number(this.env.CHAIN_ID ?? 84532);
    void (async () => {
      const naming = injected ? null : new AgentNamingClient({ rpcUrl: this.env.RPC_URL!, chainId, registry: this.env.AGENT_NAME_REGISTRY as Address, universalResolver: this.env.AGENT_NAME_UNIVERSAL_RESOLVER as Address });
      const members = await resolveMentions(refs, {
        resolveName: async (n) => injected ? injected(n) : (await naming!.resolveName(n)) as Address | null,
        // A member: the organization's own invitation record for it (S3b — for a service the invitation is the admission).
        isMember: async (a) => !!(await this.readDoc<unknown>(opts.grant, `org.invite:agent:${a.toLowerCase()}`, null)),
        exclude: [opts.principal as Address],
      });
      for (const m of members) {
        try {
          const now = new Date().toISOString();
          const messageId = generateMessageId();
          const bytes = new TextEncoder().encode(opts.bodyText);
          const envelope: MessageEnvelopeV2 = {
            version: 'ap.message.v2', id: messageId,
            conversationId: topicThreadId(opts.principal, opts.channelId),
            performative: 'REQUEST',
            from: opts.posterCaip as AnyMessageEnvelope['from'], to: [caip10(chainId, m.agent) as AnyMessageEnvelope['from']],
            subject: `@${m.label} in ${opts.entry.descriptor.title}`.slice(0, 120),
            createdAt: now, classification: 'internal',
            body: { resource: messageBodyResource(messageId), classification: 'internal', updatedAt: now },
            bodyHash: await sha256Hex32(bytes), bodyContentType: 'text/plain',
            actor: opts.posterCaip as AnyMessageEnvelope['from'],
            contextRefs: [topicContextRef(opts.principal, opts.channelId, opts.entry.descriptor.title)],
          };
          const stub = this.env.A2A_TASKS.get(this.env.A2A_TASKS.idFromName(m.agent));
          const resp = await stub.fetch(new Request(`https://do/internal/admit-message?agent=${m.agent}`, { method: 'POST', headers: internalHeaders(this.env), body: JSON.stringify({ envelope, bodyText: opts.bodyText, skill: 'messaging.mention' }) }));
          const out = (await resp.json().catch(() => ({}))) as { ok?: boolean; error?: string };
          if (!resp.ok || out.ok === false) throw new Error(out.error ?? `admit-message failed (${resp.status})`);
          await audit.write({ id: crypto.randomUUID(), timestamp: now, action: 'interactions.channels.mention', outcome: 'success', actor: { type: 'service', id: opts.principal }, subject: { type: 'channel-post', id: opts.messageId }, reason: `${m.name} told (${messageId})` });
        } catch (e) {
          void audit.write({ id: crypto.randomUUID(), timestamp: new Date().toISOString(), action: 'interactions.channels.mentionFailed', outcome: 'error', actor: { type: 'service', id: opts.principal }, subject: { type: 'channel-post', id: opts.messageId }, reason: `${m.name}: ${e instanceof Error ? e.message : String(e)}` });
        }
      }
    })().catch(() => undefined);
  }

  /** Spec 400 W2 (B7) — fire the post author's `reaction` triggers. Audited and dropped on failure (ADR-0013). */
  private dispatchReaction(opts: { entry: ChannelV1; channelId: string; principal: string; author: string; messageId: string; emoji: string; by: string; byName: string | null }): void {
    if (!internalMarker(this.env)) return;
    const author = (opts.author.match(/0x[0-9a-fA-F]{40}$/)?.[0] ?? '').toLowerCase();
    if (!author) return;
    const audit = buildAuditSink(this.env);
    void (async () => {
      const source = { kind: 'message', message: { id: opts.messageId, from: opts.by, ...(opts.byName ? { fromName: opts.byName } : {}), profile: 'reaction', text: opts.emoji, subject: `${opts.emoji} on your post in ${opts.entry.descriptor.title}`.slice(0, 120), thread: topicThreadId(opts.principal, opts.channelId), topic: { org: opts.principal, channelId: opts.channelId, title: opts.entry.descriptor.title } } };
      const stub = this.env.A2A_TASKS.get(this.env.A2A_TASKS.idFromName(author));
      const resp = await stub.fetch(new Request(`https://do/internal/fire-triggers?agent=${author}`, { method: 'POST', headers: internalHeaders(this.env), body: JSON.stringify({ source }) }));
      const out = (await resp.json().catch(() => ({}))) as { ok?: boolean; fired?: unknown[]; error?: string };
      if (!resp.ok || out.ok === false) throw new Error(out.error ?? `fire-triggers failed (${resp.status})`);
      if ((out.fired ?? []).length) await audit.write({ id: crypto.randomUUID(), timestamp: new Date().toISOString(), action: 'interactions.channels.reactionFired', outcome: 'success', actor: { type: 'user', id: opts.by }, subject: { type: 'channel-post', id: opts.messageId }, reason: `${opts.emoji} → ${author} (${(out.fired ?? []).length} trigger(s))` });
    })().catch((e) => {
      void audit.write({ id: crypto.randomUUID(), timestamp: new Date().toISOString(), action: 'interactions.channels.reactionFailed', outcome: 'error', actor: { type: 'user', id: opts.by }, subject: { type: 'channel-post', id: opts.messageId }, reason: e instanceof Error ? e.message : String(e) });
    });
  }

  /** spec 334 §6 — hand the just-adopted goal to the org's OWN agent to DRAFT a first plan
   *  revision (fire-and-forget; the A2aTaskDO runs the spec-327 planner and posts the draft back
   *  through `internal.endeavor.proposePlan`, org = actor). Every failure is AUDITED and DROPPED
   *  (ADR-0013): the steward can always author the plan by hand — no retry, no queue. */
  private dispatchEndeavorPlanDraft(principal: string, endeavorId: string, goal: string): void {
    // Unprovisioned marker ⇒ `internalHeaders` throws; these paths are best-effort and their
    // callers already swallow, so the effect is the same silence with the right cause.
    if (!internalMarker(this.env)) return;
    const audit = buildAuditSink(this.env);
    void (async () => {
      // Auto-work: when the flag is on, the SAME turn that drafts the plan continues straight into
      // adopt → execute → satisfy (the agent does the work). Off ⇒ draft-only, steward drives.
      const autoWork = (await this.state.storage.get(AUTO_WORK_FLAG_KEY)) === true;
      const stub = this.env.A2A_TASKS.get(this.env.A2A_TASKS.idFromName(principal));
      const resp = await stub.fetch(new Request(`https://do/internal/endeavor-plan?agent=${principal}`, {
        method: 'POST',
        headers: internalHeaders(this.env),
        body: JSON.stringify({ principal, endeavorId, goal, autoWork }),
      }));
      const out = (await resp.json().catch(() => ({}))) as { ok?: boolean; error?: string };
      if (!resp.ok || out.ok === false) throw new Error(out.error ?? `plan draft failed (${resp.status})`);
      await audit.write({ id: crypto.randomUUID(), timestamp: new Date().toISOString(), action: 'interactions.endeavor.planDraftDispatch', outcome: 'success', actor: { type: 'service', id: principal }, subject: { type: 'endeavor', id: endeavorId } });
    })().catch((e) => {
      void audit.write({ id: crypto.randomUUID(), timestamp: new Date().toISOString(), action: 'interactions.endeavor.planDraftFailed', outcome: 'error', actor: { type: 'service', id: principal }, subject: { type: 'endeavor', id: endeavorId }, reason: e instanceof Error ? e.message : String(e) }).catch(() => undefined);
    });
  }

  /** spec 334 §6 auto-work — run the autopilot for one endeavor (adopt latest plan if needed →
   *  execute every open step the principal can do itself → satisfy). Fire-and-forget to the
   *  principal's own A2aTaskDO; per-endeavor rate-limited so re-triggers don't stampede. Every
   *  failure is AUDITED and DROPPED (ADR-0013): the human path in Work always remains available. */
  private dispatchEndeavorWork(principal: string, endeavorId: string): void {
    // Unprovisioned marker ⇒ `internalHeaders` throws; these paths are best-effort and their
    // callers already swallow, so the effect is the same silence with the right cause.
    if (!internalMarker(this.env)) return;
    const audit = buildAuditSink(this.env);
    void (async () => {
      if ((await this.state.storage.get(AUTO_WORK_FLAG_KEY)) !== true) return;
      const key = AUTO_WORK_RATE_KEY(endeavorId);
      const prev = (await this.state.storage.get(key)) as FixedWindowState | undefined;
      const rate = fixedWindowAllow(prev, Date.now(), { windowMs: rateBound(this.env as unknown as Record<string, unknown>).windowMs, max: 1 });
      if (!rate.allowed) return;
      await this.state.storage.put(key, rate.next);
      const stub = this.env.A2A_TASKS.get(this.env.A2A_TASKS.idFromName(principal));
      const resp = await stub.fetch(new Request(`https://do/internal/endeavor-work?agent=${principal}`, {
        method: 'POST',
        headers: internalHeaders(this.env),
        body: JSON.stringify({ principal, endeavorId }),
      }));
      const out = (await resp.json().catch(() => ({}))) as { ok?: boolean; error?: string };
      if (!resp.ok || out.ok === false) throw new Error(out.error ?? `endeavor work failed (${resp.status})`);
      await audit.write({ id: crypto.randomUUID(), timestamp: new Date().toISOString(), action: 'interactions.endeavor.workDispatch', outcome: 'success', actor: { type: 'service', id: principal }, subject: { type: 'endeavor', id: endeavorId } });
    })().catch((e) => {
      void audit.write({ id: crypto.randomUUID(), timestamp: new Date().toISOString(), action: 'interactions.endeavor.workFailed', outcome: 'error', actor: { type: 'service', id: principal }, subject: { type: 'endeavor', id: endeavorId }, reason: e instanceof Error ? e.message : String(e) }).catch(() => undefined);
    });
  }

  /** spec 334 §6 auto-work — the org agent auto-triages (ADOPTS) a just-submitted request when the
   *  switch is on, so a request flows all the way to done with no human. Adoption seeds the plan
   *  draft (which, with auto-work, chains into execute). Audited + dropped on failure. */
  private dispatchEndeavorAutoAdopt(principal: string, requestId: string): void {
    // Unprovisioned marker ⇒ `internalHeaders` throws; these paths are best-effort and their
    // callers already swallow, so the effect is the same silence with the right cause.
    if (!internalMarker(this.env)) return;
    const audit = buildAuditSink(this.env);
    void (async () => {
      if ((await this.state.storage.get(AUTO_WORK_FLAG_KEY)) !== true) return;
      const stub = this.env.A2A_TASKS.get(this.env.A2A_TASKS.idFromName(principal));
      const resp = await stub.fetch(new Request(`https://do/internal/endeavor-adopt?agent=${principal}`, {
        method: 'POST',
        headers: internalHeaders(this.env),
        body: JSON.stringify({ principal, requestId }),
      }));
      const out = (await resp.json().catch(() => ({}))) as { ok?: boolean; error?: string };
      if (!resp.ok || out.ok === false) throw new Error(out.error ?? `auto-adopt failed (${resp.status})`);
      await audit.write({ id: crypto.randomUUID(), timestamp: new Date().toISOString(), action: 'interactions.endeavor.autoAdoptDispatch', outcome: 'success', actor: { type: 'service', id: principal }, subject: { type: 'endeavor-request', id: requestId } });
    })().catch((e) => {
      void audit.write({ id: crypto.randomUUID(), timestamp: new Date().toISOString(), action: 'interactions.endeavor.autoAdoptFailed', outcome: 'error', actor: { type: 'service', id: principal }, subject: { type: 'endeavor-request', id: requestId }, reason: e instanceof Error ? e.message : String(e) }).catch(() => undefined);
    });
  }

  /** EndeavorOpDeps for the principal's OWN agent acting at an internal door (the internal `x-ap-internal`
   *  marker is the authorization; the reducer's actor gate is the real authority). `steward:true` lets
   *  it take steward-gated ops (adopt request/plan) as the org acting on itself. */
  private endeavorSelfDeps(g: IncomingDelegation, principal: string, opts?: { steward?: boolean;
    /** Spec 382 — the PARTICIPANT whose finished run records its own step (in-Worker, marker-gated; the
     *  reducer still re-gates: only the managing principal or an active participant may satisfy a step). */
    actor?: string }): EndeavorOpDeps {
    const chainId = Number(this.env.CHAIN_ID ?? 84532);
    const doorAudit = buildAuditSink(this.env);
    const actor = (opts?.actor && /^0x[0-9a-fA-F]{40}$/.test(opts.actor) ? opts.actor : principal).toLowerCase();
    return {
      principal,
      // Spec 375 — the events a commit appends fire the participants' triggers, off the mutex.
      onCommitted: (endeavorId, events, state) => { this.state.waitUntil(afterEndeavorCommit(this.env, principal as Address, endeavorId, events as never, state).catch(() => undefined)); },
      principalCaip: caip10(chainId, principal as Address),
      sessionSa: actor,
      sessionCaip: caip10(chainId, actor as Address),
      readDoc: <T,>(resource: string, empty: T): Promise<T> => this.readDoc<T>(g, resource, empty),
      writeDoc: (resource: string, data: unknown): Promise<void> => this.writeDoc(g, resource, data),
      serialize: <T,>(fn: () => Promise<T>): Promise<T> => this.serialize(fn),
      memberName: async () => (actor === principal.toLowerCase() ? 'Organization agent' : 'Participant agent'),
      isSteward: async () => opts?.steward ?? false,
      verifySignature: (account, digest, signature) => this.erc1271(account as Address, digest as Hex, signature as Hex),
      writeAudit: (action, subject, timestamp) =>
        doorAudit.write({ id: crypto.randomUUID(), timestamp: timestamp ?? new Date().toISOString(), action, outcome: 'success', actor: { type: 'service', id: principal }, subject }),
      putTopicBody: async (envelope, bodyText) => {
        const store = createVaultMessageBodyStore(this.vaultFor(g), principal);
        await store.putBody({ messageId: envelope.id, bytes: new TextEncoder().encode(bodyText), contentType: 'text/plain', classification: 'internal', resource: envelope.body.resource });
      },
      draftPlanForGoal: (endeavorId, goal) => this.dispatchEndeavorPlanDraft(principal, endeavorId, goal),
    };
  }

  /** spec 328 §3 — post-commit person-inbox assistant scan. Called (fire-and-forget) after ANY
   *  inbox.data commit — the in-Worker a2a merge (`internal.deliver`) and the Home's whole-doc
   *  write (`inbox.put`) — so every ingress triggers identically. The seen-ledger RMW rides the
   *  DO's single-writer mutex (queued, never awaited by the caller — the caller may itself hold
   *  the mutex); the trigger evaluation + dispatch run off the lock. Every drop/failure is
   *  AUDITED and DROPPED (ADR-0013): no retry, no queue, no effect on the committed delivery. */
  private queueInboxAssistantScan(principal: string, envelopes: MessageEnvelopeV1[]): void {
    const audit = buildAuditSink(this.env);
    // Unprovisioned marker ⇒ `internalHeaders` throws; these paths are best-effort and their
    // callers already swallow, so the effect is the same silence with the right cause.
    if (!internalMarker(this.env)) return;
    void this.serialize<MessageEnvelopeV1[]>(async () => {
      if (!(await this.state.storage.get(INBOX_ASSISTANT_FLAG_KEY))) return [];
      const seen = (await this.state.storage.get(INBOX_ASSISTANT_SEEN_KEY)) as string[] | undefined;
      const ids = envelopes.map((e) => e.id);
      if (!seen) {
        // First sight (enable seeds explicitly; this covers a DO-storage reset): SEED, never dispatch.
        await this.state.storage.put(INBOX_ASSISTANT_SEEN_KEY, ids.slice(-INBOX_ASSISTANT_SEEN_CAP));
        return [];
      }
      const seenSet = new Set(seen);
      const fresh = envelopes.filter((e) => !seenSet.has(e.id));
      if (fresh.length === 0) return [];
      await this.state.storage.put(INBOX_ASSISTANT_SEEN_KEY, [...seen, ...fresh.map((e) => e.id)].slice(-INBOX_ASSISTANT_SEEN_CAP));
      return fresh;
    }).then(async (fresh) => {
      if (fresh.length === 0) return;
      // Canonical enablement + config: the VAULT record (the flag above is only the O(1) gate cache).
      const st = ((await this.state.storage.get('state')) ?? {}) as StoredState;
      const g = st.grant;
      if (!g) return;
      const cfg = await this.readDoc<PersonAssistantV1 | null>(g, PERSON_ASSISTANT_RESOURCE, null);
      const now = Date.now();
      const candidates = fresh.filter((e) => inboxAssistantTrigger(cfg, e, principal, now)).slice(0, INBOX_ASSISTANT_MAX_PER_SCAN);
      for (const envelope of candidates) {
        const rateKey = INBOX_ASSISTANT_RATE_KEY(envelope.conversationId);
        const prev = (await this.state.storage.get(rateKey)) as FixedWindowState | undefined;
        const rate = fixedWindowAllow(prev, Date.now(), rateBound(this.env as unknown as Record<string, unknown>));
        if (!rate.allowed) {
          await audit.write({ id: crypto.randomUUID(), timestamp: new Date().toISOString(), action: 'interactions.inboxAssistant.rateLimited', outcome: 'denied', actor: { type: 'service', id: principal }, subject: { type: 'conversation', id: envelope.conversationId } });
          continue;
        }
        await this.state.storage.put(rateKey, rate.next);
        try {
          const stub = this.env.A2A_TASKS.get(this.env.A2A_TASKS.idFromName(principal));
          const resp = await stub.fetch(new Request(`https://do/internal/inbox-respond?agent=${principal}`, {
            method: 'POST',
            headers: internalHeaders(this.env),
            body: JSON.stringify({
              principal, conversationId: envelope.conversationId, messageId: envelope.id,
              senderCaip: envelope.from, ...(envelope.subject ? { subject: envelope.subject } : {}),
              displayName: cfg?.displayName ?? '',
            }),
          }));
          const out = (await resp.json().catch(() => ({}))) as { ok?: boolean; error?: string };
          if (!resp.ok || out.ok === false) throw new Error(out.error ?? `inbox assistant respond failed (${resp.status})`);
          await audit.write({ id: crypto.randomUUID(), timestamp: new Date().toISOString(), action: 'interactions.inboxAssistant.dispatch', outcome: 'success', actor: { type: 'service', id: principal }, subject: { type: 'conversation', id: envelope.conversationId } });
        } catch (e) {
          await audit.write({ id: crypto.randomUUID(), timestamp: new Date().toISOString(), action: 'interactions.inboxAssistant.dispatchFailed', outcome: 'error', actor: { type: 'service', id: principal }, subject: { type: 'conversation', id: envelope.conversationId }, reason: e instanceof Error ? e.message : String(e) }).catch(() => undefined);
        }
      }
    }).catch((e) => {
      void audit.write({ id: crypto.randomUUID(), timestamp: new Date().toISOString(), action: 'interactions.inboxAssistant.dispatchFailed', outcome: 'error', actor: { type: 'service', id: principal }, subject: { type: 'inbox', id: principal }, reason: e instanceof Error ? e.message : String(e) }).catch(() => undefined);
    });
  }

  private async erc1271(account: Address, digest: Hex, signature: Hex): Promise<boolean> {
    if (this.deps?.erc1271) return this.deps.erc1271(account, digest, signature);
    try {
      const magic = (await this.pub().readContract({ address: account, abi: ERC1271_ABI, functionName: 'isValidSignature', args: [digest, signature] })) as Hex;
      return magic.toLowerCase() === ERC1271_MAGIC;
    } catch { return false; }
  }

  /** One delegation-authorized demo-mcp tool call (bound-mint transport). NEW-C1 — per-op transport
   *  selection: when the principal has custodied a DEL-001 session leaf (st.sessionLeaf,
   *  PRINCIPAL-signed, binding the interactions-session KMS key) AND that key is configured,
   *  CLIENT-MINT a bound token (callMcpToolBound, enforceBinding) — the leaf's delegator MUST equal
   *  this grant's delegator (the principal / token sub), else it's not the right principal's leaf. */
  /** Spec 410 §3 — remember what this object did for a logical operation, when the caller named one. */
  private async recordOperation(body: Record<string, unknown>, kind: OpLedgerRecord['kind'], ref: string): Promise<void> {
    const opId = typeof body.operationId === 'string' ? body.operationId.trim() : '';
    if (!opId || opId.length > 200) return;
    await this.state.storage.put(OP_LEDGER_KEY(opId), { kind, ref, at: new Date().toISOString() } satisfies OpLedgerRecord);
    await this.sweepOpLedger();
  }
  /** Spec 410 §3 — the ledger's expiry: one bounded page of `op:` rows per write, the expired ones deleted. */
  private async sweepOpLedger(): Promise<void> {
    const now = Date.now();
    const page = await this.state.storage.list<OpLedgerRecord>({ prefix: 'op:', limit: OP_LEDGER_SWEEP_PAGE });
    const dead = [...page.entries()].filter(([, rec]) => rec && typeof rec.at === 'string' && opLedgerExpired(rec, now)).map(([k]) => k);
    if (dead.length) await this.state.storage.delete(dead);
  }

  private async mcpVaultTool(
    grant: IncomingDelegation,
    toolName: 'get_vault_record' | 'get_vault_records' | 'set_vault_record' | 'list_vault_record',
    toolArgs: Record<string, unknown>,
  ): Promise<Response> {
    if (this.deps?.vaultTool) return this.deps.vaultTool(grant, toolName, toolArgs);
    const env = this.env;
    // Same predicate as /agent/interactions-session-key and interactionsSessionAccount: GCP KMS in
    // production, A2A_INTERACTIONS_SESSION_PRIVATE_KEY on a local stack. Gating on the GCP name alone
    // here made local dev fail-closed even though the enable ceremony had custodied a leaf for the
    // dev key — the two gates MUST agree or a leaf gets minted that ops then refuse to use.
    if (interactionsSessionKeyConfigured(env)) {
      const st = ((await this.state.storage.get('state')) ?? {}) as StoredState;
      // Route A — sign under the LIVE ladder rung (falls back to the single legacy leaf). When the ladder is
      // exhausted there is no live rung, so we fall through to session_leaf_required (the endeavor pre-flight
      // has already turned that into an actionable needsReEnable for the surfaces that poll).
      const leaf = this.activeLeaf(st);
      if (leaf && leaf.delegator.toLowerCase() === grant.delegator.toLowerCase()) {
        // ONE THROTTLE MECHANISM FOR EVERY VAULT TOOL (spec 382, found live). demo-mcp's stage-2 soft
        // limiter (120 verified calls / 60 s per principal) rejects with the same opaque 401 as a credential
        // failure; the read/write adapters retried it, the getMany call sites did not, and a busy
        // organization — its own work turns spending its budget beside a steward's ops — surfaced
        // "auth failed" for what was a throttle. The retry lives HERE now, under every tool, bounded and
        // honouring the limiter's own retryAfterMs (capped), and a throttle that persists is SAID to be one.
        let last: Response | null = null;
        for (let attempt = 0; attempt < 4; attempt++) {
          countVaultCall(toolName, { throttled: attempt > 0 });
          const resp = await callMcpToolBound({ env, toolName, grant, sessionLeaf: leaf, toolArgs });
          if (resp.status !== 401 && resp.status !== 429) return resp;
          const peek = resp.clone();
          const out = (await peek.json().catch(() => ({}))) as { code?: string; retryAfterMs?: number };
          if (out.code !== 'rate-limited') return resp;
          last = resp;
          if (attempt === 3) break;
          const wait = Math.min(Math.max(Number(out.retryAfterMs ?? 0) || 0, InteractionsDO.VAULT_THROTTLE_BACKOFF_MS * (attempt + 1)), 2_500);
          await new Promise((r) => setTimeout(r, wait));
        }
        return new Response(JSON.stringify({ ok: false, code: 'rate-limited', error: InteractionsDO.vaultThrottledError(toolName).message }), { status: last?.status ?? 429, headers: { 'Content-Type': 'application/json' } });
      }
      // CRIT-2 W4 — the interactions-session key IS configured but this principal has NO custodied leaf
      // (it enabled before leaf-signing shipped). FAIL-CLOSED (ADR-0013 one-mechanism): require a
      // re-enable to custody the DEL-001 leaf; do NOT switch to the server-mint bridge. Server-mint is
      // retired. The Home's activateInteractionsIfNeeded self-heals this on the principal's next login.
      return new Response(
        JSON.stringify({ ok: false, error: 'session_leaf_required', detail: 'interactions vault access needs a re-enable to custody the DEL-001 session leaf (server-mint retired — CRIT-2)' }),
        { status: 409, headers: { 'Content-Type': 'application/json' } },
      );
    }
    // CRIT-2 W6 — server-mint retired. The interactions-session key is REQUIRED for interactions vault
    // ops (bound-mint above / DO-side proof). Unconfigured ⇒ FAIL-CLOSED (provision
    // GCP_KMS_INTERACTIONS_KEY_NAME, or A2A_INTERACTIONS_SESSION_PRIVATE_KEY on a local stack); prod
    // always sets the KMS name, taking the bound/409 branch above. No fallback.
    return new Response(
      JSON.stringify({ ok: false, error: 'interactions_key_unprovisioned', detail: 'no interactions-session key configured (GCP_KMS_INTERACTIONS_KEY_NAME / dev A2A_INTERACTIONS_SESSION_PRIVATE_KEY) — interactions vault ops require it (server-mint retired, CRIT-2)' }),
      { status: 503, headers: { 'Content-Type': 'application/json' } },
    );
  }

  // 2026-07-18 LIVE REGRESSION — a THROTTLED vault call is not an auth failure. demo-mcp's stage-2
  // soft rate limiter (120 verified calls/60s per principal+capability) rejects with the same opaque
  // 401 `{ error: 'auth failed', code: 'rate-limited' }` as a credential reject, and this DO used to
  // rethrow that string verbatim: a member opening a busy org's Discussions board saw a raw
  // "auth failed" instead of the board. The limiter rejects BEFORE the tool handler runs (nothing
  // executed), and its window frees in well under a second (observed retryAfterMs 8–394ms), so a
  // rate-limited response is RETRIED with a short backoff and, if it persists, surfaces as an
  // explicit throttle error — never as an authorization verdict.
  private static readonly VAULT_THROTTLE_BACKOFF_MS = 250;
  private static vaultThrottledError(op: string): Error {
    return new Error(`vault ${op} throttled (rate-limited) — this agent's storage budget is momentarily exhausted; retry shortly`);
  }

  /**
   * The fabric Vault port over the delegation-authorized demo-mcp transport (plane B).
   *
   * THE `owner` ARGUMENT IS NOT THE OWNER — the GRANT is. Every record this adapter reaches is scoped by
   * the delegation it carries, so demo-mcp resolves the owner from the grant's delegator and this
   * parameter is inert. That is why ~20 call sites in this file pass `owner: ''` and it works.
   *
   * IT WAS ALSO A LATENT DIVERGENCE. The adapter DESTRUCTURED `owner` away, so a caller passing something
   * else was silently ignored — and the mounted gateway's vault tool passes `owner: principal`. The two
   * planes agreed only because the argument was dropped, and the day anyone taught this adapter to honour
   * `owner`, InteractionsDO (`''`) and the gateway (the principal) would have disagreed instantly, with a
   * symptom that reads like an authorization bug.
   *
   * So it is CHECKED rather than dropped: a non-empty `owner` must equal the grant's delegator. Empty
   * stays legal (the established in-file convention), a matching value is now proven rather than assumed,
   * and a mismatched one is a loud error instead of a silent no-op.
   */
  private vaultFor(grant: IncomingDelegation): Vault {
    const callTool = (toolName: 'get_vault_record' | 'get_vault_records' | 'set_vault_record' | 'list_vault_record', toolArgs: Record<string, unknown>): Promise<Response> =>
      this.mcpVaultTool(grant, toolName, toolArgs);
    const assertOwner = (owner: string): void => {
      if (!owner) return; // the in-file convention: the grant names the owner
      if (owner.toLowerCase() !== grant.delegator.toLowerCase()) {
        throw new Error(
          `vault owner mismatch: caller asked for ${owner} but this grant is the delegator ${grant.delegator}'s — ` +
            'the grant determines whose vault this reaches, and honouring the argument would cross principals',
        );
      }
    };
    return {
      async write({ owner, resource, data }: { owner: string; resource: string; data: unknown; classification?: string }): Promise<void> {
        assertOwner(owner);
        // A rate-limited write was rejected at verify time (never executed) — same bounded retry as reads.
        for (let attempt = 0; attempt < 4; attempt++) {
          const resp = await callTool('set_vault_record', { recordType: resource, data });
          const out = (await resp.json().catch(() => ({}))) as { ok?: boolean; error?: string; code?: string };
          if (resp.ok && out.ok !== false) return;
          if (isRetryableVaultToolFailure(resp.status, out)) {
            if (attempt < 3) { await new Promise((r) => setTimeout(r, InteractionsDO.VAULT_THROTTLE_BACKOFF_MS * (attempt + 1))); continue; }
            throw InteractionsDO.vaultThrottledError('write');
          }
          throw new Error(out.error ?? `vault write failed (${resp.status})`);
        }
        throw InteractionsDO.vaultThrottledError('write');
      },
      async read<T>({ owner, resource }: { owner: string; resource: string }): Promise<{ data: T } | null> {
        assertOwner(owner);
        // BOUNDED RETRY (2026-07-11) — cold-cache first read; demo-mcp caches the deterministic vault-key
        // verdict, so only the first op per isolate touches the chain. A real empty (`ok:true, record:null`)
        // returns immediately — empty is an answer, an auth error is not (ADR-0013: retry the SAME call).
        // NOTE: get_vault_record returns the payload under `data` (NOT `record`) — the field-name mismatch
        // was THE "saved but reads back empty" bug.
        let lastErr = 'vault read failed';
        for (let attempt = 0; attempt < 4; attempt++) {
          const resp = await callTool('get_vault_record', { recordType: resource });
          const out = (await resp.json().catch(() => ({}))) as { ok?: boolean; data?: T | null; error?: string; code?: string };
          if (!resp.ok) {
            // Transient throughput reject (stage-2 limiter) ⇒ back off + retry; never an auth verdict.
            if (isRetryableVaultToolFailure(resp.status, out)) {
              if (attempt < 3) { await new Promise((r) => setTimeout(r, InteractionsDO.VAULT_THROTTLE_BACKOFF_MS * (attempt + 1))); continue; }
              throw InteractionsDO.vaultThrottledError('read');
            }
            // demo-mcp returns `{ error, detail }` — and `detail` is the only thing that says WHY.
            // Dropping it turned every server-side vault fault into the word "internal error", which
            // is indistinguishable from a denial and cost hours of bisecting to get back.
            throw new Error([out.error ?? `vault read failed (${resp.status})`, (out as { detail?: string }).detail].filter(Boolean).join(' — '));
          }
          if (out.ok === false) { lastErr = out.error ?? 'vault read unauthorized'; if (attempt < 3) { await new Promise((r) => setTimeout(r, 120)); continue; } throw new Error(lastErr); }
          return out.data === null || out.data === undefined ? null : { data: out.data };
        }
        throw new Error(lastErr);
      },
      // spec 315 — enumerate the owner's OWN vault record types. demo-mcp's list_vault_record is
      // record-scope-FILTERED to the interactions grant, so this returns ONLY the Home-managed records
      // (app-specific records under other grants stay invisible — least-privilege). Bare record types.
      async list(): Promise<Array<{ resource: string; updatedAt: string }>> {
        const resp = await callTool('list_vault_record', {});
        const out = (await resp.json().catch(() => ({}))) as { ok?: boolean; records?: Array<{ record_type: string; updated_at: string }>; error?: string };
        if (!resp.ok || out.ok === false) throw new Error(out.error ?? `vault list failed (${resp.status})`);
        return (out.records ?? []).map((r) => ({ resource: r.record_type, updatedAt: r.updated_at }));
      },
    } as unknown as Vault;
  }

  /**
   * MOUNT a co-resident `PrincipalGatewayDO` over this grant, with the MCP-backed vault INJECTED.
   *
   * Lazy and per-grant. Lazy because constructing the gateway runs the `CREATE TABLE IF NOT EXISTS` of
   * every store it owns, and those tables should exist only for principals who actually call a mounted
   * op — not for everyone, on the chance that someone might. Per-grant because `vaultFor` binds the
   * requester, and a gateway cached across grants would serve one principal's read under another's
   * authority, which is the one mistake that would make this migration worse than not doing it.
   *
   * `vault` is injected; `exchangeStore` / `interactionStore` are not, and so are DO-local. That is
   * permitted here ONLY because the mounted op touches neither. When an op reaches the exchange stream
   * the amendment's three conditions come due — the durable fact written to the vault first, an explicit
   * rebuild in code, and a test that wipes the DO and rebuilds it — and they are not met today.
   */
  private mountedGateway(grant: IncomingDelegation): PrincipalGatewayDO {
    const chainId = Number(this.env.CHAIN_ID ?? 84532);
    const manager = (this.env.DELEGATION_MANAGER ?? '') as Address;
    const vault = this.vaultFor(grant);
    const deps = buildMountedGatewayDeps({
      vault,
      // The gateway is built around ONE grant, so the token parameter carries nothing and is ignored —
      // there is no second grant it could name. The verification below is the real one either way.
      verify: async () => {
        const d: Delegation = {
          ...grant,
          salt: BigInt(grant.salt),
          caveats: grant.caveats.map((c) => ({ enforcer: c.enforcer, terms: c.terms, args: (c.args ?? '0x') as Hex })),
        } as Delegation;
        const digest = hashDelegation(d, chainId, manager);
        // Signature, then revocation. Both, because either alone is a different and weaker claim: a valid
        // signature on a revoked delegation is exactly what revocation exists to defeat, and this verdict
        // is about to be CACHED — so a check skipped here is a check skipped for every warm call after it.
        if (!(await this.erc1271(grant.delegator as Address, digest, grant.signature as Hex))) return null;
        try {
          const revoked = (await this.pub().readContract({
            address: manager, abi: IS_REVOKED_ABI, functionName: 'isRevoked', args: [digest as Hex],
          })) as boolean;
          if (revoked) return null;
        } catch {
          return null; // an unavailable revocation check is a refusal, never an assumption of validity
        }
        return {
          principal: grant.delegator.toLowerCase(),
          sessionKey: grant.delegate.toLowerCase(),
          delegationHash: digest,
          // The epoch keys verdict invalidation (spec 311). `chainId:manager` is the real thing that
          // changes on a full reset — new contracts, new DelegationManager — so cached verdicts from the
          // previous deployment cannot be mistaken for current ones. Not a placeholder.
          epoch: `${chainId}:${manager.toLowerCase()}`,
          manager: manager.toLowerCase(),
        };
      },
    });
    return new PrincipalGatewayDO(this.state as never, this.env as never, deps);
  }

  /** Last shadow sample, per isolate. In memory: it bounds ADDED LOAD, and a bound that survives isolate
   *  recycle would mean a durable write on the hottest read path to save one sampled read. */
  private lastShadowAt: number | undefined;
  /** Divergence evidence, in memory + bounded. Diagnostics with the shelf life of one investigation. */
  private divergences: Divergence[] = [];

  /**
   * Read the inbox record THROUGH the mounted gateway. The ONE gateway read path — both the explicit
   * `gateway.inbox.get` probe and the shadow comparison call this, because two gateway read paths would
   * drift and the shadow would then be comparing InteractionsDO against something no probe ever exercised.
   */
  private async gatewayReadInbox(grant: IncomingDelegation, principal: string): Promise<unknown> {
    const gw = this.mountedGateway(grant);
    const verdict = await gw.verifyAndCache(GATEWAY_GRANT_TOKEN);
    if (!verdict) throw new Error('gateway refused the grant');
    const out = await gw.invokeFast({
      key: verdict,
      // Single-use, so a pollable read must vary its id or the second poll reads as a replay. Bound to the
      // principal + resource so it stays a request id rather than a nonce under another name.
      requestId: `gw:${principal.toLowerCase()}:${INBOX_RESOURCE}:${crypto.randomUUID()}`,
      now: new Date().toISOString(),
      tool: 'get_vault_record',
      args: { recordType: INBOX_RESOURCE },
      // Caveat pass (B) — never cached, run on every invoke, pinned to the one resource this op mirrors.
      // The grant's own scope is re-enforced at demo-mcp, which remains the authority (ADR-0041); a pass
      // that returned `true` unconditionally would make the gateway's three-part check a two-part one.
      runCaveatPass: async (_v, tool, args) => tool === 'get_vault_record' && args.recordType === INBOX_RESOURCE,
    });
    if (!out.ok) throw new Error(`gateway refused the read: ${out.reason}`);
    return (out.result as { data?: unknown } | null)?.data ?? null;
  }

  /**
   * Run the gateway alongside the served answer and record whether they agree (adoption rung 2).
   *
   * FIRE-AND-FORGET, AND DELIBERATELY SO. The response has already been decided by the time this runs. A
   * shadow that could delay the response would make adoption cost latency on every poll, and one that
   * could throw would let a diagnostic break the op it was diagnosing — which is a worse bug than any it
   * could find.
   */
  private shadowInboxGet(grant: IncomingDelegation, served: unknown): void {
    const now = Date.now();
    if (!shouldShadow({ lastShadowAt: this.lastShadowAt, now, intervalMs: SHADOW_INTERVAL_MS })) return;
    this.lastShadowAt = now; // set BEFORE awaiting: two concurrent polls must not both sample
    const principal = (grant.delegator ?? '').toLowerCase();
    const at = new Date(now).toISOString();
    void (async () => {
      try {
        const shadow = await this.gatewayReadInbox(grant, principal);
        // The RE-READ (audit G-4). A delivery landing between the serving read and the shadow read changes
        // the document legitimately, and the two planes then honestly report different instants. Without
        // this, every busy principal manufactures `value` divergences that mean nothing — and a report full
        // of benign differences is worse than no report, because the mechanism loses credibility exactly
        // when it is about to be trusted for a promotion. Serving path, run again: same mechanism.
        const servedAgain = await this.readDoc<unknown>(grant, INBOX_RESOURCE, null);
        this.divergences = recordDivergence(
          this.divergences,
          classifyDivergence({ op: 'inbox.get', served, shadow, servedAgain, at }),
        );
      } catch (e) {
        // A gateway error is EVIDENCE, recorded like any other outcome — it is the most informative thing
        // a shadow can find, and an op whose shadow errors is one that must not be promoted.
        this.divergences = recordDivergence(this.divergences, {
          op: 'inbox.get', at, kind: 'gateway-error', detail: e instanceof Error ? e.message : String(e),
        });
      }
    })();
  }

  /** BATCHED message-body read: ONE `get_vault_records` round-trip for a whole topic's bodies,
   *  hash-verified per envelope (fabric `verifiedBodiesFromBatch` — the same spec 309 §8.4
   *  verification as `loadBody`, one mechanism). Replaces the per-message delegated reads whose
   *  O(board size) call volume per poll exhausted the org principal's stage-2 verified-call budget
   *  (the 2026-07-18 live regression: gate reads on the same budget then rejected and the member's
   *  board surfaced a raw "auth failed"). Requires demo-mcp ≥ VL-W2 (`get_vault_records`, deployed
   *  2026-07-13) — the deployed fleet has it; there is deliberately NO per-record fallback path
   *  (ADR-0013 one-mechanism). Fail-closed PER RECORD: unverifiable bodies are omitted. */
  private async readTopicBodies(grant: IncomingDelegation, envelopes: AnyMessageEnvelope[]): Promise<Record<string, string>> {
    if (envelopes.length === 0) return {};
    const recordTypes = [...new Set(envelopes.map((e) => e.body.resource))];
    let records: Record<string, unknown> = {};
    for (let attempt = 0; attempt < 4; attempt++) {
      const resp = await this.mcpVaultTool(grant, 'get_vault_records', { recordTypes });
      const out = (await resp.json().catch(() => ({}))) as { ok?: boolean; records?: Record<string, unknown>; error?: string; code?: string };
      if (!resp.ok || out.ok === false) {
        if (isRetryableVaultToolFailure(resp.status, out)) {
          if (attempt < 3) { await new Promise((r) => setTimeout(r, InteractionsDO.VAULT_THROTTLE_BACKOFF_MS * (attempt + 1))); continue; }
          throw InteractionsDO.vaultThrottledError('read');
        }
        throw new Error(out.error ?? `vault batch read failed (${resp.status})`);
      }
      records = out.records ?? {};
      break;
    }
    const bytes = await verifiedBodiesFromBatch(envelopes, records);
    const decoder = new TextDecoder();
    return Object.fromEntries(Object.entries(bytes).map(([id, b]) => [id, decoder.decode(b)]));
  }

  /**
   * WHAT THIS ORGANIZATION RECORDS OF ONE MEMBER (spec 427 §5.3) — the record, the role on it, and the offer that role
   * came from; never the delegation, which is the member's own. Two callers, one reading: the member's own session
   * (`org.membership.mine`, the key derived from the session) and the member's own AGENT asking in-Worker on a run
   * the member started (`internal.member.role`, capability `person.roles.list`). Neither can name somebody else:
   * the first has no such argument and the second is called only with the run's verified asker.
   * A workspace holds no members; asked of one, the answer names the organization that does.
   */
  private async membershipAnswer(grant: IncomingDelegation, principal: string, member: string): Promise<Record<string, unknown>> {
    const me = member.toLowerCase();
    const rec = await this.readDoc<Record<string, unknown> | null>(grant, `org.membership:member:${me}`, null);
    if (!rec || String(rec.memberAgent ?? '').toLowerCase() !== me) {
      const governor = governorOf(await this.readDoc<unknown>(grant, WORKSPACE_GOVERNOR_RECORD, null).catch(() => null));
      return { ok: true, organization: principal.toLowerCase(), membership: null, ...(governor && governor !== principal.toLowerCase() ? { governedBy: governor } : {}) };
    }
    const ra = (rec.roleAssignment ?? {}) as Record<string, unknown>;
    const { materializedByDelegation: _wire, ...roleAssignment } = ra;
    return {
      ok: true,
      organization: principal.toLowerCase(),
      membership: { ...rec, roleAssignment: { assignedRole: PLAIN_MEMBER, ...roleAssignment } },
      ended: typeof rec.endedAt === 'string' && !!rec.endedAt,
      offer: offerFromRoleFields(roleAssignment as Partial<AssignedRoleFields>),
    };
  }

  /**
   * THE ROLE ON A MEMBERSHIP IS REPLACED (spec 427 §3.3): the role fields change, the delegation that materializes
   * the membership and the household facets stay. Two callers, one write: a steward's session presenting the
   * stewardship wire (`org.setMemberRole`), and the organization's own agent on a run that presented the
   * organization's MANDATE for the act (`internal.member.setRole`, capability `organization.member.role.set`).
   * Whoever calls has already been judged; this only writes, audits and tells the room.
   */
  private async setMemberRole(grant: IncomingDelegation, principal: string, member: string, fields: AssignedRoleFields, actor: string, audit: ReturnType<typeof buildAuditSink>): Promise<Response> {
    return this.serialize(async () => {
      const key = `org.membership:member:${member}`;
      const rec = await this.readDoc<Record<string, unknown> | null>(grant, key, null);
      if (!rec) return json({ ok: false, code: 'no_membership', error: 'that agent holds no membership record here — a role hangs on a membership' }, 404);
      if (typeof rec.endedAt === 'string' && rec.endedAt) return json({ ok: false, code: 'membership_ended', error: 'that membership has ended — invite them back, with the role' }, 409);
      const before = (rec.roleAssignment ?? {}) as Partial<AssignedRoleFields>;
      await this.writeDoc(grant, key, { ...rec, roleAssignment: { ...withoutRoleFields(rec.roleAssignment as Record<string, unknown>), ...fields } });
      await audit.write({ id: crypto.randomUUID(), timestamp: fields.assignedAt ?? new Date().toISOString(), action: 'interactions.org.membership.role', outcome: 'success', actor: { type: 'user', id: actor }, subject: { type: 'membership', id: member } });
      const say = async () => { try { await this.postWelcome(grant, principal, `🎭 ${await this.boardNameFor(grant, member)} is now ${fields.roleName ?? 'a member'} here.`, true); } catch { /* narration, never the fact */ } };
      const later = (this.state as { waitUntil?: (p: Promise<unknown>) => void }).waitUntil;
      if (typeof later === 'function') later.call(this.state, say()); else await say();
      return json({ ok: true, member, role: fields.assignedRole, ...(fields.roleName ? { roleName: fields.roleName } : {}), previous: before.assignedRole ?? PLAIN_MEMBER, changed: (before.roleDefinitionId ?? '') !== (fields.roleDefinitionId ?? '') || (before.assignedRole ?? PLAIN_MEMBER) !== fields.assignedRole });
    });
  }

  private async readDoc<T>(grant: IncomingDelegation, resource: string, empty: T): Promise<T> {
    const r = await this.vaultFor(grant).read<T>({ owner: '', resource });
    return (r?.data as T) ?? empty;
  }

  private async writeDoc(grant: IncomingDelegation, resource: string, data: unknown): Promise<void> {
    await this.vaultFor(grant).write({ owner: '', resource, data, classification: 'internal' } as never);
    // What admission and naming are derived from changed: the remembered admissions are dropped, never served stale.
    if (resource === DIRECTORY_RESOURCE || resource === LOCAL_NAMES_RESOURCE || resource.startsWith('org.membership:')) this.presenceMemo.clear();
  }

  /** GATE-TIME listing verification (spec 322 §4): current + ERC-1271-proven + not tombstoned. */
  private async memberName(grant: IncomingDelegation, principal: string, sessionSaCaip: string): Promise<string | null> {
    const rows = await this.readDoc<IndexedListing[]>(grant, DIRECTORY_RESOURCE, []);
    const me = sessionSaCaip.toLowerCase();
    const now = new Date().toISOString();
    const mine = rows.find((l) => l.listing.subject.toLowerCase() === me && isListingCurrent(l.listing, now));
    if (!mine) return null;
    const st = ((await this.state.storage.get('state')) ?? {}) as StoredState;
    if (st.subjects?.[me]?.tombstoned) return null;
    const { proof, ...draft } = mine.listing;
    const digest = await sha256Hex32(canonicalizeMessage(draft));
    const subjectAddr = mine.listing.subject.match(/0x[0-9a-fA-F]{40}$/)?.[0] as Address | undefined;
    if (!subjectAddr || !(await this.erc1271(subjectAddr, digest as Hex, proof.signature as Hex))) return null;
    void principal;
    return mine.listing.displayName;
  }

  /** Does the wire carry the STEWARDSHIP shape, not a data grant? (SEC-C1). A stewardship/site
   *  delegation (`buildApprovedSiteDelegation`) carries an `allowedTargetsEnforcer` caveat (governance
   *  targets: agent-relationship / naming / registry) and NEVER a vault-record-scope caveat. Every
   *  org→person DATA grant — member-access, membership, delivery, interactions — instead carries a
   *  VAULT_RECORD_SCOPE_ENFORCER caveat. Requiring the governance caveat AND rejecting the scope
   *  caveat separates a steward from a member: without this, a member's own org→member member-access
   *  delegation (same delegator=org, delegate=member, org-signed, unrevoked) passed as a steward
   *  proof → member→steward escalation (kick members, dump the ledger, act as steward). */
  /**
   * Liveness + authenticity for an org wire: delegator, delegate, caveats, revocation, signature.
   *
   * The four call sites each rebuilt this. They were NOT missing revocation — a correction to the
   * audit that called them a partial verify — but four copies is four chances to drop one.
   *
   * Deliberately says nothing about SHAPE. `hasStewardshipShape` and the record-scope test above are
   * app authorization policy and stay where they are: no generic "required enforcers" list can say
   * "allowedMethods must be ABSENT" or "these terms must name the governance registries".
   */
  private async verifyWire(wire: IncomingDelegation, expectedDelegator: string, sessionSa: Address): Promise<boolean> {
    // Memo hit: this exact wire was proven valid within the TTL — skip the two chain reads. The signature
    // identifies the wire; delegator+delegate pin the expectation the proof was made against.
    const memoKey = `${expectedDelegator.toLowerCase()}:${sessionSa.toLowerCase()}:${wire.signature ?? ''}`;
    const now = Date.now();
    const exp = this.verifyMemo.get(memoKey);
    if (exp !== undefined) {
      if (exp > now) return true;
      this.verifyMemo.delete(memoKey);
    }
    const ok = await verifyDelegationWire({
      wire: wire as unknown as DelegationWireLike,
      expectedDelegator,
      expectedDelegate: sessionSa,
      enforcers: enforcersFromEnv(this.env as unknown as Record<string, string | undefined>),
      checks: {
        digest: (d) => hashDelegation(d, Number(this.env.CHAIN_ID ?? 84532), this.env.DELEGATION_MANAGER as Address),
        erc1271: (signer, digest, sig) => this.erc1271(signer, digest, sig),
        isRevoked: async (digest) =>
          (await this.pub().readContract({
            address: this.env.DELEGATION_MANAGER as Address,
            abi: IS_REVOKED_ABI,
            functionName: 'isRevoked',
            args: [digest],
          })) as boolean,
      },
    });
    if (ok) {
      // Only cache a proven-valid wire. Prune expired entries (and a few of the oldest if we are at the
      // cap) so the memo stays bounded on a busy object.
      if (this.verifyMemo.size >= InteractionsDO.VERIFY_MEMO_MAX) {
        for (const [k, e] of this.verifyMemo) if (e <= now) this.verifyMemo.delete(k);
        while (this.verifyMemo.size >= InteractionsDO.VERIFY_MEMO_MAX) {
          const oldest = this.verifyMemo.keys().next().value;
          if (oldest === undefined) break;
          this.verifyMemo.delete(oldest);
        }
      }
      this.verifyMemo.set(memoKey, now + InteractionsDO.VERIFY_MEMO_TTL_MS);
    }
    return ok;
  }

  private hasStewardshipShape(wire: IncomingDelegation): boolean {
    // NEW-H2 — FAIL CLOSED on an unconfigured enforcer. If ALLOWED_TARGETS_ENFORCER is unset (wrangler
    // binds "" for a placeholder var), the old `enforcer(c) === ''` matched ANY caveat with a missing/empty
    // enforcer → a record-scoped member wire (with a blank-enforcer caveat) would pass as stewardship
    // (member→steward escalation). A stewardship wire is unrecognizable without the real governance-targets
    // address, so no address ⇒ no stewardship.
    const targetEnforcer = (this.env.ALLOWED_TARGETS_ENFORCER ?? '').toLowerCase();
    if (!/^0x[0-9a-f]{40}$/.test(targetEnforcer)) return false;
    const caveats = wire.caveats ?? [];
    const enforcer = (c: { enforcer?: string }): string => (c.enforcer ?? '').toLowerCase();

    // STEWARD-SHAPE-CONFUSION-1 — stewardship must be a POSITIVE identity, not "allowedTargets present ∧ no
    // record-scope". Payment mandates ([payment, timestamp, allowedTargets, allowedMethods]) and A2A message
    // grants ([timestamp, allowedTargets, allowedMethods]) ALSO carry allowedTargets and no record-scope, so
    // the old negative test accepted any of them as a steward proof → member/outsider → steward escalation
    // (the SEC-C1 hole reached through a different wire shape). The genuine steward/site wire
    // (`buildSiteDelegation`/`siteCaveats`): carries NO allowedMethods and NO record-scope caveat, AND its
    // allowedTargets terms pin the GOVERNANCE contracts (agentRelationship + agentNameRegistry + subregistry).
    // A payment mandate targets an asset; an a2a grant targets the recipient agent — neither names the
    // governance registries — and both add allowedMethods, so both are rejected here.
    const methodsEnforcer = (this.env.ALLOWED_METHODS_ENFORCER ?? '').toLowerCase();
    if (methodsEnforcer && caveats.some((c) => enforcer(c) === methodsEnforcer)) return false; // a2a grant / payment mandate
    if (caveats.some((c) => enforcer(c) === VAULT_RECORD_SCOPE_ENFORCER.toLowerCase())) return false; // data grant (SEC-C1)

    const rel = (this.env.AGENT_RELATIONSHIP ?? '').toLowerCase();
    const reg = (this.env.AGENT_NAME_REGISTRY ?? '').toLowerCase();
    // Fail closed if we can't positively identify the governance targets (prod injects both; org-create
    // already depends on them). No governance anchor ⇒ no stewardship.
    if (!/^0x[0-9a-f]{40}$/.test(rel) || !/^0x[0-9a-f]{40}$/.test(reg)) return false;
    const targetsCav = caveats.find((c) => enforcer(c) === targetEnforcer);
    if (!targetsCav?.terms) return false;
    let targets: string[];
    try {
      targets = (decodeAbiParameters([{ type: 'address[]' }], targetsCav.terms as Hex)[0] as readonly Address[]).map((a) => a.toLowerCase());
    } catch { return false; }
    // The site wire pins [agentRelationship, agentNameRegistry, subregistry]; require BOTH registries to be
    // present so a wire whose allowedTargets name anything else (asset, agent SA, host endpoint) is not
    // stewardship.
    return targets.includes(rel) && targets.includes(reg);
  }

  /** Organization-resource-access proof (SEC-H1): a presented org→member organizationResourceAccessDelegation wire — the ORG's
   *  authorization that this person may join (minted at invite time, `issueMemberAccessDelegation`).
   *  delegator = the org (this principal), delegate = the caller, org-signed + unrevoked, AND
   *  carrying the DATA-grant shape (a vault-record-scope caveat) so a governance/stewardship wire
   *  can't be replayed here. Without it a self-signed listing alone made anyone a member of any org
   *  (self-join → read its private channels). */
  private async hasMemberAccess(principal: string, sessionSa: Address, wire: IncomingDelegation | undefined): Promise<boolean> {
    if (!wire) return false;
    if (wire.delegator.toLowerCase() !== principal.toLowerCase()) return false;
    if (wire.delegate.toLowerCase() !== sessionSa.toLowerCase()) return false;
    const hasRecordScope = (wire.caveats ?? []).some((c) => (c.enforcer ?? '').toLowerCase() === VAULT_RECORD_SCOPE_ENFORCER.toLowerCase());
    if (!hasRecordScope) return false; // a stewardship/governance wire is not member-access
    // SHAPE decided above (app policy); LIVENESS decided by the substrate.
    return this.verifyWire(wire, principal, sessionSa);
  }

  // ── THE WELCOME TOPIC — every organization board opens with one, and it narrates arrivals ──────────
  //
  // A board with no first topic is a room with no door: the first thing a person sees should tell them
  // where they are. So every organization's board is DEFAULTED with a "Welcome" topic, created the first
  // time the board is read if it is missing, and the organization's own agent posts a line into it as
  // invitations go out and people join or decline. Those lines are NOT authority — an invitation and a
  // membership are still the records the substrate reads; this is the room saying so out loud.
  private async ensureWelcomeTopic(grant: IncomingDelegation, principal: string, locked = false): Promise<ChannelV1 | null> {
    const index = await this.readDoc<ChannelV1[]>(grant, CONVERSATION_INDEX_RESOURCE, []);
    const existing = index.find((c) => c.title.trim().toLowerCase() === 'welcome');
    if (existing) return existing;
    const orgCaip = caip10(Number(this.env.CHAIN_ID ?? 84532), principal as Address) as ChannelV1['descriptor']['owner'];
    const create = async () => {
      const fresh = await this.readDoc<ChannelV1[]>(grant, CONVERSATION_INDEX_RESOURCE, []);
      const again = fresh.find((c) => c.title.trim().toLowerCase() === 'welcome');
      if (again) return again;
      const r = createBoardChannel(fresh, { contextId: principal, owner: orgCaip, title: 'Welcome', createdBy: 'the organization', participationPolicy: 'open', members: [], creatorSa: principal });
      if (!r.ok) return null;
      await this.writeDoc(grant, CONVERSATION_INDEX_RESOURCE, fresh);
      return fresh.find((c) => c.title.trim().toLowerCase() === 'welcome') ?? null;
    };
    // `locked` = the caller already holds the DO's write lock (serialize is not re-entrant).
    return locked ? create() : this.serialize(create);
  }

  /** A line in the Welcome topic, authored BY THE ORGANIZATION (its public name), never by a caller.
   *  Best-effort: a board that cannot be written never fails the act it narrates. `locked` as above. */
  private async postWelcome(grant: IncomingDelegation, principal: string, bodyText: string, locked = false): Promise<void> {
    try {
      const topic = await this.ensureWelcomeTopic(grant, principal, locked);
      if (!topic) return;
      const names = await this.resolvePublicNames([principal]).catch(() => ({} as Record<string, string | null>));
      const orgName = names[principal.toLowerCase()] ?? 'the organization';
      const orgCaip = caip10(Number(this.env.CHAIN_ID ?? 84532), principal as Address) as AnyMessageEnvelope['from'];
      const post = async () => {
        const messages = await this.readDoc<ChannelMessageEntryV1[]>(grant, TOPIC_RESOURCE(topic.descriptor.id), []);
        const composed: ChannelV1[] = [{ ...topic, messages }];
        const r = await appendBoardPost(composed, { channelId: topic.descriptor.id, from: orgCaip, authorName: orgName, bodyText, actor: orgCaip });
        if (!r.ok) return;
        const store = createVaultMessageBodyStore(this.vaultFor(grant), principal);
        await store.putBody({ messageId: r.envelope.id, bytes: new TextEncoder().encode(bodyText), contentType: 'text/plain', classification: 'internal', resource: r.envelope.body.resource });
        await this.writeDoc(grant, TOPIC_RESOURCE(topic.descriptor.id), composed[0]!.messages);
        await buildAuditSink(this.env).write({ id: crypto.randomUUID(), timestamp: r.envelope.createdAt, action: 'interactions.channels.welcomePost', outcome: 'success', actor: { type: 'service', id: principal }, subject: { type: 'conversation', id: topic.descriptor.id } });
      };
      await (locked ? post() : this.serialize(post));
    } catch (e) {
      console.log(`[welcome] ${principal}: could not post — ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  /** How a member is called on the board: their org-local name, else their public name, else a short address. */
  private async boardNameFor(grant: IncomingDelegation, agent: string): Promise<string> {
    const a = agent.toLowerCase();
    const local = (await this.readLocalNames(grant).catch(() => ({} as Record<string, string>)))[a];
    if (local) return local;
    const pub = (await this.resolvePublicNames([a]).catch(() => ({} as Record<string, string | null>)))[a];
    return pub ?? `${a.slice(0, 6)}…${a.slice(-4)}`;
  }

  private async readLocalNames(grant: IncomingDelegation): Promise<Record<string, string>> {
    const raw = await this.readDoc<Record<string, string>>(grant, LOCAL_NAMES_RESOURCE, {});
    return raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : {};
  }

  /** Live public names for member addresses, cached briefly per instance. The stored publish-time
   *  `label` is NOT reused for this: it froze whatever the subject was called then, and since
   *  nameless members joined it may be an org-local slug — presenting either as a naming-service
   *  name would be a lie the reader cannot detect. A resolver failure yields null (fail-closed:
   *  the roster renders without a public name, never with a guessed one). */
  /** Whether THIS principal is a service agent — by its on-chain derived type when a profile resolver is
   *  configured, else by its typed name (`*.svc`). Unknown reads as NOT a service: the check refuses a
   *  service a write, and an unreadable chain must not refuse a person hers. Memoised for the object's life. */
  private serviceKind: Promise<boolean> | null = null;
  private principalIsService(principal: string): Promise<boolean> {
    if (this.serviceKind) return this.serviceKind;
    this.serviceKind = (async () => {
      if (!this.env.RPC_URL || !this.env.AGENT_NAME_REGISTRY || !this.env.AGENT_NAME_UNIVERSAL_RESOLVER) return false;
      const naming = new AgentNamingClient({
        rpcUrl: this.env.RPC_URL, chainId: Number(this.env.CHAIN_ID ?? 84532),
        registry: this.env.AGENT_NAME_REGISTRY as Address, universalResolver: this.env.AGENT_NAME_UNIVERSAL_RESOLVER as Address,
        ...(this.env.PROFILE_RESOLVER ? { profileResolver: this.env.PROFILE_RESOLVER as Address } : {}),
      });
      const me = principal as Address;
      if (this.env.PROFILE_RESOLVER) {
        const d = await naming.readDerivedType(me).catch(() => null);
        if (d?.agentType) return d.agentType === 'service';
      }
      const name = await naming.reverseResolve(me).catch(() => null);
      return typeof name === 'string' && /\.svc$/i.test(name);
    })().catch(() => false);
    return this.serviceKind;
  }

  private publicNameCache = new Map<string, { name: string | null; at: number }>();
  private async resolvePublicNames(addrs: readonly string[]): Promise<Record<string, string | null>> {
    const out: Record<string, string | null> = {};
    if (!this.env.RPC_URL || !this.env.AGENT_NAME_REGISTRY || !this.env.AGENT_NAME_UNIVERSAL_RESOLVER) return out;
    const naming = new AgentNamingClient({
      rpcUrl: this.env.RPC_URL,
      chainId: Number(this.env.CHAIN_ID ?? 84532),
      registry: this.env.AGENT_NAME_REGISTRY as Address,
      universalResolver: this.env.AGENT_NAME_UNIVERSAL_RESOLVER as Address,
    });
    const now = Date.now();
    const TTL = 5 * 60_000;
    await Promise.all(
      [...new Set(addrs.map((a) => a.toLowerCase()))].filter((a) => /^0x[0-9a-f]{40}$/.test(a)).slice(0, 64).map(async (a) => {
        const hit = this.publicNameCache.get(a);
        if (hit && now - hit.at < TTL) { out[a] = hit.name; return; }
        const name = await naming.reverseResolve(a as Address).catch(() => null);
        this.publicNameCache.set(a, { name, at: now });
        out[a] = name;
      }),
    );
    return out;
  }

  /** An org-scoped facet — never an address. The address stays the identity. */
  private normalizeLocalName(raw: unknown): string | null {
    const s = String(raw ?? '').trim().replace(/\s+/g, ' ');
    if (s.length < 1 || s.length > 80) return null;
    if (/^0x[0-9a-fA-F]{40}$/.test(s) || /^eip155:/i.test(s)) return null;
    return s;
  }

  /**
   * Who may enter this community's channels, and how they are known here.
   *
   * Admission is one of three independent proofs — a current listing, a member-access grant, or
   * stewardship. The name is a facet: a local name they chose, else the listing displayName, else
   * "Steward". The canonical person address is never the name.
   */
  /** A POSITIVE admission, remembered 30 s per (principal · session subject · the wires presented) — the topic read's
   *  slowest stage (1.5–4.5 s, measured 2026-10-05 from the field gateway) for an answer that does not change between a
   *  topic's list, read and post. ONLY admissions are kept (a refusal is asked again), and the TTL bounds how long a
   *  revoked listing, grant or stewardship can go unnoticed — the same rule as `verifyMemo` (20 s) and the governor's
   *  member memo (60 s). Presenting a different wire is a different key, so it is checked afresh. */
  private static readonly PRESENCE_MEMO_TTL_MS = 30_000;
  private presenceMemo = new Map<string, { until: number; value: { admitted: true; steward: boolean; listed: boolean; you: string | null } }>();

  private async communityPresence(
    grant: IncomingDelegation,
    principal: string,
    sessionSa: Address,
    sessionCaip: string,
    body: Record<string, unknown>,
  ): Promise<{ admitted: boolean; steward: boolean; listed: boolean; you: string | null }> {
    const presented = JSON.stringify({ s: body.stewardship ?? null, m: body.memberAccess ?? null });
    const digest = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(presented)))).map((b) => b.toString(16).padStart(2, '0')).join('');
    const key = `${principal.toLowerCase()}|${sessionSa.toLowerCase()}|${digest}`;
    const now = Date.now();
    const hit = this.presenceMemo.get(key);
    if (hit && hit.until > now) return hit.value;
    const out = await this.computeCommunityPresence(grant, principal, sessionSa, sessionCaip, body);
    if (out.admitted) {
      if (this.presenceMemo.size >= 256) this.presenceMemo.clear();
      this.presenceMemo.set(key, { until: now + InteractionsDO.PRESENCE_MEMO_TTL_MS, value: { admitted: true, steward: out.steward, listed: out.listed, you: out.you } });
    }
    return out;
  }

  private async computeCommunityPresence(
    grant: IncomingDelegation,
    principal: string,
    sessionSa: Address,
    sessionCaip: string,
    body: Record<string, unknown>,
  ): Promise<{ admitted: boolean; steward: boolean; listed: boolean; you: string | null }> {
    // The listing read, the steward proof (two chain reads) and the local-names doc do not depend on one
    // another; issued together they cost one round trip, not three. Names are read before admission is
    // decided — the read is under the ORG's grant either way and nothing of it leaves for a refused caller.
    const [listingName, steward, names] = await Promise.all([
      this.memberName(grant, principal, sessionCaip),
      this.isSteward(principal, sessionSa, body.stewardship as IncomingDelegation | undefined),
      this.readLocalNames(grant),
    ]);
    const memberAccess =
      listingName || steward
        ? false
        : await this.hasMemberAccess(principal, sessionSa, body.memberAccess as IncomingDelegation | undefined);
    // Spec 382 — THE ORGANIZATION'S OWN MEMBERSHIP RECORD is the fourth proof. `org.membership:member:<sa>`
    // is what the roster answers from (aporg:OrganizationMembership, written by the member for themselves
    // with the grant that materializes it); a member the organization lists and the roster names was
    // still refused at this door for want of a listing or an org→member grant — members admitted by the
    // harness's invitation, or before the directory wave, hold neither. Read back, the record is checked
    // against the chain: the member's grant must still be theirs and unrevoked.
    const recordedName = listingName || steward || memberAccess ? null : await this.recordedMemberName(grant, principal, sessionSa);
    // The fifth: a member of the organization that GOVERNS this workspace (the owner's rule, 2026-10-02 — a
    // workspace holds no members; they belong to its governor). Reads already go through the governor (spec
    // 424); without this a member could read the workspace and never open a topic on its board. The board,
    // its topics and its assistant stay the WORKSPACE's — only where membership is read moves.
    const governedName = listingName || steward || memberAccess || recordedName ? null : await this.governedMemberName(grant, principal, sessionSa);
    if (!listingName && !steward && !memberAccess && !recordedName && !governedName) {
      return { admitted: false, steward: false, listed: false, you: null };
    }
    const local = names[sessionSa.toLowerCase()];
    const localName = typeof local === 'string' && local.trim() ? local.trim() : null;
    let publicName: string | null = null;
    if (!localName && !listingName && !recordedName && !governedName && !steward) {
      const resolved = await this.resolvePublicNames([sessionSa]);
      const hit = resolved[sessionSa.toLowerCase()];
      publicName = typeof hit === 'string' && hit.trim() ? hit.trim() : null;
    }
    const you = localName ?? listingName ?? recordedName ?? governedName ?? publicName ?? (steward ? 'Steward' : null);
    return { admitted: true, steward, listed: !!listingName, you };
  }

  /** Spec 382 — the organization's own record that this session's principal is a CURRENT member, its grant
   *  re-checked against the chain. The display name it records, or null. Never authority (ADR-0041). */
  private async recordedMemberName(grant: IncomingDelegation, principal: string, sessionSa: Address): Promise<string | null> {
    const me = sessionSa.toLowerCase();
    type MembershipRec = { type?: string; memberAgent?: string; organizationAgent?: string; displayName?: string; endedAt?: string; roleAssignment?: { materializedByDelegation?: IncomingDelegation } };
    let rec: MembershipRec | null = null;
    try { rec = await this.readDoc<MembershipRec | null>(grant, `org.membership:member:${me}`, null); } catch { return null; }
    if (!rec || rec.type !== 'ap.org.membership.v1' || rec.endedAt) return null;
    if (String(rec.memberAgent ?? '').toLowerCase() !== me || String(rec.organizationAgent ?? '').toLowerCase() !== principal.toLowerCase()) return null;
    const wire = rec.roleAssignment?.materializedByDelegation;
    if (!wire || String(wire.delegator ?? '').toLowerCase() !== me || String(wire.delegate ?? '').toLowerCase() !== principal.toLowerCase()) return null;
    try {
      const d: Delegation = { ...wire, salt: BigInt(wire.salt), caveats: (wire.caveats ?? []).map((c) => ({ enforcer: c.enforcer, terms: c.terms, args: (c.args ?? '0x') as Hex })) } as Delegation;
      const digest = hashDelegation(d, Number(this.env.CHAIN_ID ?? 84532), this.env.DELEGATION_MANAGER as Address);
      if (!(await this.erc1271(me as Address, digest, wire.signature as Hex))) return null;
      const revoked = (await this.pub().readContract({ address: this.env.DELEGATION_MANAGER as Address, abi: IS_REVOKED_ABI, functionName: 'isRevoked', args: [digest] })) as boolean;
      if (revoked) return null;
    } catch { return null; } // unverifiable is not verified (ADR-0013)
    const name = String(rec.displayName ?? '').trim();
    return name || 'Member';
  }

  /** This workspace's governing organization (its own `workspace.governor` pointer), or null — an organization,
   *  a person, or a legacy workspace holds none. Remembered for a few minutes: a pairing is chartered once. */
  private governorMemo: { at: number; governor: string | null } | null = null;
  private static readonly GOVERNOR_MEMO_TTL_MS = 300_000;
  /** A positive answer from the governor, remembered a minute (the club standing's rule): the burst of board
   *  reads that opens a topic must not cost one DO hop each. Only TRUE is kept, so an ended membership is
   *  refused within the minute. */
  private governedMemberMemo = new Map<string, { until: number; name: string }>();

  /** Spec 424 — the board gate's governed-workspace proof: the session's principal is a CURRENT member of the
   *  organization that governs this workspace, answered by that organization's own object
   *  (`internal.member.recorded`). The display name it records, or null. Never authority (ADR-0041). */
  private async governedMemberName(grant: IncomingDelegation, principal: string, sessionSa: Address): Promise<string | null> {
    const now = Date.now();
    if (!this.governorMemo || now - this.governorMemo.at > InteractionsDO.GOVERNOR_MEMO_TTL_MS) {
      let doc: unknown;
      try { doc = await this.readDoc<unknown>(grant, WORKSPACE_GOVERNOR_RECORD, null); } catch (e) {
        // A grant signed before `vault:workspace.governor` was in its scope is DENIED this read (it reads as "no
        // governor" until re-issued). Remembered a minute, not five, and said once — every refused caller would
        // otherwise repeat a read that cannot succeed.
        console.log(`[board-gate] ${principal} workspace.governor unreadable — ${(e instanceof Error ? e.message : String(e)).slice(0, 120)}`);
        this.governorMemo = { at: now - InteractionsDO.GOVERNOR_MEMO_TTL_MS + 60_000, governor: null };
        return null;
      }
      const read = governorOf(doc);
      this.governorMemo = { at: now, governor: read ? read.toLowerCase() : null };
    }
    const governor = this.governorMemo.governor;
    if (!governor || governor === principal.toLowerCase() || !this.env.INTERACTIONS) return null;
    const me = sessionSa.toLowerCase();
    const hit = this.governedMemberMemo.get(me);
    if (hit && hit.until > now) return hit.name;
    try {
      const stub = this.env.INTERACTIONS.get(this.env.INTERACTIONS.idFromName(governor));
      const resp = await stub.fetch(new Request(`https://do/interactions/${governor}/internal.member.recorded`, {
        method: 'POST', headers: internalHeaders(this.env), body: JSON.stringify({ member: me }),
      }));
      const out = (await resp.json().catch(() => ({}))) as { ok?: boolean; name?: string | null };
      const name = resp.ok && out.ok && typeof out.name === 'string' && out.name.trim() ? out.name.trim() : null;
      if (name) {
        if (this.governedMemberMemo.size >= 256) this.governedMemberMemo.clear();
        this.governedMemberMemo.set(me, { until: now + 60_000, name });
      }
      return name;
    } catch { return null; } // unanswerable is not a member (ADR-0013)
  }

  /**
   * A SCOPED READ wire is sufficient to READ one resource — the caveat decides, not the shape.
   *
   * WHY THIS IS NOT "MEMBERS CAN READ EVERYTHING". The tempting version of this admits any
   * member-access wire for `content.get`, which grants the whole org's content to anyone in the body
   * and can never be narrowed afterwards. This instead asks the wire what it actually authorizes:
   * a vault-record-scope caveat naming resources and ops, evaluated against THIS resource for `read`.
   * A wire that does not name it is refused, so the same mechanism scales from "read everything" down
   * to "read the progress records of one community" with no second code path.
   *
   * NO SCOPE ⇒ NO. `vaultRecordScopeAllows` returns TRUE for an empty scope set (an unscoped grant is
   * unrestricted), which is right for its own callers and exactly wrong here: it would make a wire
   * with no record-scope caveat — including a stewardship wire arriving on the wrong field — pass as a
   * scoped read. The caveat's PRESENCE is what makes this a data grant, so its absence fails first.
   *
   * WRITES AND DELETES GO THROUGH THE SAME DOOR, with the op the caller is actually performing —
   * `content.put` carrying `data: null` is a DELETE, and admitting it as a write would let a grant
   * that says `ops: ['write']` erase records. The op is decided at the call site from the payload,
   * not inferred here.
   *
   * NEVER THE AGGREGATE. `content.catalog` is one record listing every artifact in the organization,
   * so a scoped writer who could rewrite it could drop another community's records from the index
   * while holding a grant that names only their own. The call site refuses it before asking; there is
   * no scope string that should buy it, which is why the refusal is structural and not a policy line.
   */
  private async hasScopedAccess(
    principal: string,
    sessionSa: Address,
    wire: IncomingDelegation | undefined,
    resource: string,
    op: 'read' | 'write' | 'delete',
  ): Promise<{ ok: false } | { ok: true; grants: VaultRecordScopeGrant[] }> {
    if (!wire || !resource) return { ok: false };
    if (wire.delegator.toLowerCase() !== principal.toLowerCase()) return { ok: false };
    if (wire.delegate.toLowerCase() !== sessionSa.toLowerCase()) return { ok: false };
    const cav = (wire.caveats ?? []).find(
      (c) => (c.enforcer ?? '').toLowerCase() === VAULT_RECORD_SCOPE_ENFORCER.toLowerCase(),
    );
    if (!cav?.terms) return { ok: false }; // see NO SCOPE ⇒ NO above
    let grants;
    try {
      grants = decodeVaultRecordScopeTerms(cav.terms as Hex);
    } catch {
      return { ok: false }; // undecodable terms grant nothing
    }
    if (grants.length === 0) return { ok: false };
    // `vault:`-PREFIXED, because that is the namespace grant resources are written in
    // (`buildVaultRecordScopeCaveat` rejects anything else, and REQUIRED_SCOPES above is all
    // `vault:*`). The op's `resource` arrives bare — `content.artifact.<id>` — so comparing the two
    // unprefixed would never match any real grant and this would refuse every scoped read while
    // looking like it worked.
    if (!vaultRecordScopeAllows(grants, { server: vaultServerId(this.env), resource: `vault:${resource}`, op })) return { ok: false };
    // SHAPE + SCOPE decided above (app policy); LIVENESS by the substrate, same as every other proof.
    return (await this.verifyWire(wire, principal, sessionSa)) ? { ok: true, grants } : { ok: false };
  }

  /** Steward proof: a presented org→person organizationStewardshipDelegation wire, org-verified + unrevoked on-chain, AND
   *  carrying the stewardship caveat shape (SEC-C1 — never a data grant). */
  private async isSteward(principal: string, sessionSa: Address, wire: IncomingDelegation | undefined): Promise<boolean> {
    if (!wire) return false;
    if (wire.delegator.toLowerCase() !== principal.toLowerCase()) return false;
    if (wire.delegate.toLowerCase() !== sessionSa.toLowerCase()) return false;
    if (!this.hasStewardshipShape(wire)) return false; // SEC-C1: a member-access grant is NOT stewardship
    // SHAPE decided above (app policy — a positive identity test); LIVENESS by the substrate.
    return this.verifyWire(wire, principal, sessionSa);
  }


  /** Does the stored grant cover the CURRENT wave's scope set? Stale ⇒ steward re-enables. */
  private grantIsCurrent(grant: IncomingDelegation): boolean {
    const cav = (grant.caveats ?? []).find((c) => (c.enforcer ?? '').toLowerCase() === VAULT_RECORD_SCOPE_ENFORCER.toLowerCase());
    if (!cav?.terms) return false;
    try {
      const resources = new Set(decodeVaultRecordScopeTerms(cav.terms as Hex).flatMap((g) => g.resources));
      return REQUIRED_SCOPES.every((r) => resources.has(r));
    } catch { return false; }
  }

  /**
   * Does the stored session leaf still delegate to the key this DO actually signs with?
   *
   * `true` when there is no leaf at all — absence is a different state (the principal predates the leaf
   * and uses the older path), and reporting it as stale would make every such principal re-sign for no
   * gain. Unreadable signer config also returns `true`: an unprovisioned key is already reported by its
   * own fail-closed path, and turning that into "stale" would ask a principal to re-issue a leaf that
   * cannot be minted yet.
   */
  /**
   * Spec 412 W5 — IS THE LEAF STILL LIVE? A DEL-001 session leaf is time-boxed (12 h at issue) and nothing re-issued it:
   * the DO went on signing under an expired leaf, every release its agent minted verified "invalid — not live at
   * publishedAt", and `status` said `current: true` (a Google-custodied publisher, 2026-09-21). `null` when there is no
   * leaf or its window cannot be read; else whether NOW is inside it. Reported on status so the Home re-issues the leaf
   * on the person's next visit, and consulted before the DO signs as the agent.
   */
  /** Spec 423 §2.1 route A — THE PRE-APPROVED LEAF LADDER. A steward signs N session leaves at once, their windows
   *  tiling forward (each `[0, now + (i+1)·T]`), so a live leaf exists for N·T without the steward returning. The
   *  ladder is `st.sessionLeaves`; a legacy single `st.sessionLeaf` is just a one-rung ladder (back-compat — an org
   *  enabled before route A keeps working unchanged). */
  private leafLadder(st: StoredState): IncomingDelegation[] {
    return st.sessionLeaves && st.sessionLeaves.length ? st.sessionLeaves : (st.sessionLeaf ? [st.sessionLeaf] : []);
  }
  /** Is this one leaf's timestamp window live now? `null` when it carries no readable window. */
  private leafWindowLive(leaf: IncomingDelegation): boolean | null {
    const ts = (leaf.caveats ?? []).find((c) => (c.enforcer ?? '').toLowerCase() === String(this.env.TIMESTAMP_ENFORCER ?? '').toLowerCase());
    if (!ts?.terms) return null;
    try {
      const w = decodeTimestampTerms(ts.terms as Hex);
      const now = BigInt(Math.floor(Date.now() / 1000));
      return now >= w.validAfter && now < w.validUntil;
    } catch { return null; }
  }
  /** The LIVE rung the DO signs under: the first ladder leaf whose window contains now. `undefined` when the
   *  ladder is exhausted (every rung expired) — which is `needsReEnable` territory, caught before a vault read. */
  private activeLeaf(st: StoredState): IncomingDelegation | undefined {
    return this.leafLadder(st).find((l) => this.leafWindowLive(l) === true);
  }

  sessionLeafLive(st: StoredState): boolean | null {
    const ladder = this.leafLadder(st);
    if (!ladder.length) return null;                                   // no leaf at all — absence, not staleness
    if (ladder.some((l) => this.leafWindowLive(l) === true)) return true; // a rung is live
    // No rung is live: expired if any window was readable (→ re-enable); null only if none could be read.
    return ladder.some((l) => this.leafWindowLive(l) !== null) ? false : null;
  }

  private async sessionLeafMatchesSigner(st: StoredState): Promise<boolean> {
    // Every rung binds the SAME session key (built together at enable), so the active rung — or any, for a
    // status read when none is live — answers for all.
    const leaf = this.activeLeaf(st) ?? this.leafLadder(st)[0];
    if (!leaf?.delegate) return true;
    try {
      const acct = await interactionsSessionAccount(this.env);
      return acct.address.toLowerCase() === String(leaf.delegate).toLowerCase();
    } catch {
      return true;
    }
  }

  /**
   * Spec 408 §2.1 — DOES THE STORED LEAF CARRY AN AUDIENCE? A DEL-001 session leaf must name the delegates its
   * key may present the principal's grants to (`SESSION_AUDIENCE_ENFORCER`); demo-mcp now REJECTS a leaf that
   * names none ("session-delegation names no audience"). A leaf minted before 408 carries no such caveat, so
   * every vault read it fuels fails at mcp with a bare "auth failed" — while `sessionLeafLive`/`-MatchesSigner`
   * both report fine (the leaf is neither expired nor mis-signed), so `status.current` stayed true and the
   * Home's self-heal SKIPPED it forever. This closes that blind spot: a PRESENT leaf with no (or empty)
   * audience is stale and must be re-issued. `true` when there is no leaf at all — absence is a different state
   * (handled by the fail-closed session_leaf_required path), not a reason to force a re-issue. (2026-10-03,
   * found live: alice's pre-408 org leaves 409-stormed the Work page; see the org-leaf-decay incident.)
   */
  private sessionLeafAudienceOk(st: StoredState): boolean {
    const leaf = this.activeLeaf(st) ?? this.leafLadder(st)[0];
    if (!leaf) return true;
    const c = (leaf.caveats ?? []).find((x) => (x.enforcer ?? '').toLowerCase() === SESSION_AUDIENCE_ENFORCER.toLowerCase());
    if (!c?.terms) return false;
    try { return decodeSessionAudienceTerms(c.terms as Hex).length > 0; } catch { return false; }
  }

  /** The deterministic ways a PRESENT leaf ladder is stale (every rung expired · wrong signer · no spec-408
   *  audience), as one predicate. A principal on the older no-leaf path is NOT stale (empty ladder). */
  private async sessionLeafStale(st: StoredState): Promise<boolean> {
    if (!this.leafLadder(st).length) return false;
    return this.sessionLeafLive(st) === false || !this.sessionLeafAudienceOk(st) || !(await this.sessionLeafMatchesSigner(st));
  }

  /** Bridge-HMAC gate for the Home-server channel (SEC-010 envelope; audience pins the op). */
  private async bridgeGate(request: Request, rawBody: string, op: string): Promise<{ ok: true } | { ok: false; reason: string }> {
    const secret = this.env.A2A_CUSTODY_BRIDGE_SECRET;
    const kv = this.env.BRIDGE_NONCES;
    if (!secret || !kv) return { ok: false, reason: 'bridge not configured' };
    const nonces: NonceStore = nonceStoreFromKv(kv);
    return verifyBridgeCall({ request, rawBody, secret, expectedAudience: `interactions.${op}`, nonces });
  }

  /** spec 323 W4 — the PORTABLE gate for owner-facing residency ops: the OWNER's broker session
   *  (verifyHomeSession, session SA === principal) is accepted DIRECTLY, so ANY Home holding the
   *  owner's session drives them with NO shared bridge secret. Caller-selected (not a fallback,
   *  ADR-0013): a request that carries `session` takes the Web3-authenticated owner path; one that
   *  carries the SEC-010 envelope instead takes the incumbent demo-a2a↔Home server transport. Each
   *  fails closed. (Non-owner-facing ops — invite.* — stay bridge-only: they are org-steward /
   *  token-redeem substrate flows, not the owner acting on their own records.) */
  private async ownerOrBridge(
    request: Request,
    rawBody: string,
    op: string,
    principal: string,
    session: string,
    /**
     * spec 341 §1 — the ORG case. An org has no session, so a steward reading its inbox fails the
     * `sa === principal` test by definition. Presenting the org's stewardship delegation is how they
     * prove the right to, and it is the SAME proof `applications.*` and `content.*` already take.
     *
     * Without this the org path had no option but the shared secret — not because a secret was the
     * right authority, but because nothing else could express "this person may act for this org".
     */
    stewardship?: IncomingDelegation,
  ): Promise<{ ok: true; clientId?: string } | { ok: false; reason: string }> {
    if (session) {
      // A HOME SESSION **OR** A RELYING id_token, exactly as the skills block below already accepts
      // (spec 341 §4.2). The asymmetry was the spec-323-W4 hole: `verifyHomeSession` pins
      // `aud = DEMO_SSO_AUD`, and a relying app's token carries `aud = client_id`, so a real Connect
      // client — which holds an id_token and a site delegation and no Home session — could not read its
      // own user's mail. A downstream migration reverted over exactly this.
      //
      // WHY THIS IS NOT A BEARER BECOMING AUTHORITY. The vault read does not run on the token: it runs
      // on `st0.grant`, a delegation the PERSON signed, ERC-1271-verified when it was stored and
      // carrying `vault:inbox.data` in its record scope, which demo-mcp re-enforces per record. The
      // token decides only *may this caller ask the DO to use the grant it already holds*, and the
      // answer is bounded to `sa === principal` — you may read your own mail and nobody else's.
      //
      // WHAT IS STILL MISSING, stated so it is not mistaken for done: revoking ONE app means revoking
      // its OIDC client registration, not a delegation, because every caller shares the principal's
      // one grant. Per-app revocation needs a per-app scoped grant (§4.1) and is a separate wave.
      //
      // Caller-selected, never a fallback (ADR-0013): a request carrying `session` takes this path and
      // fails closed here; one carrying the SEC-010 envelope takes the bridge. Neither is tried after
      // the other fails, and a bad token does NOT fall through to the secret.
      const home = await verifyHomeSession(session, this.env);
      if (home.ok) {
        if (home.sa.toLowerCase() === principal) {
          // The person's own control plane. No clientId ⇒ the read runs under the principal's own grant.
          return { ok: true };
        }
        if (await this.isSteward(principal, home.sa, stewardship)) return { ok: true };
        return { ok: false, reason: 'these records belong to the principal — self access, or a steward presenting its stewardship delegation' };
      }
      const relying = await verifyRelyingIdToken(session, this.env);
      if (!relying.ok) return { ok: false, reason: home.error };
      if (relying.sa.toLowerCase() !== principal) return { ok: false, reason: 'these records belong to the principal — self access only' };
      // A relying app never acts for an ORG here: stewardship is a person's relationship to an
      // organization, and an app holding that person's token has not been given it.
      if (stewardship) return { ok: false, reason: 'stewardship is presented by the steward, not by an app acting as them' };
      // A relying APP. Carry its verified identity out so the read can run under THAT app's grant.
      return { ok: true, clientId: relying.clientId };
    }
    return this.bridgeGate(request, rawBody, op);
  }

  /**
   * spec 341 §5.3 — the STEWARD gate for an ORGANIZATION's governance docs.
   *
   * `ownerOrBridge` cannot serve these: their principal is an org, an org has no session, and its
   * steward's session SA is by definition NOT the principal. So those ops stayed bridge-only — a
   * shared secret standing in for authority, which is exactly what this spec exists to remove.
   *
   * The proof is the org's stewardship delegation, verified the same way `messaging.*` and
   * `consult.routingEnable` verify it: delegator is this org, delegate is the caller, stewardship
   * SHAPE not merely member access (SEC-C1), ERC-1271-live and unrevoked. That is strictly stronger
   * than the secret it replaces — the secret proves the CALLER is our Home, and nothing about whether
   * the person behind it may act for this organization.
   *
   * Caller-selected, never a fallback (ADR-0013): a request carrying `session` takes the delegation
   * path and fails closed there; one carrying the SEC-010 envelope takes the bridge. Neither is tried
   * after the other fails.
   *
   * IDENTITY IS EITHER TOKEN; AUTHORITY IS ALWAYS THE DELEGATION. `verifyHomeSession` pins
   * `aud = DEMO_SSO_AUD`, so a REGISTERED relying app — which by construction holds `aud = client_id`
   * — was refused here even when the person behind it stewards the org. That is the same asymmetry
   * §4.2 already closed for `ownerOrBridge`, left open on the steward path: an org's Content
   * Artifacts were reachable from the Home and from nowhere else, so every Connect client had to
   * either give up or reach for the shared secret.
   *
   * WHY ACCEPTING THE SECOND TOKEN GRANTS NOTHING NEW. Both verifiers resolve to a PERSON's SA and
   * nothing more; the decision that follows is `isSteward(principal, sa, stewardship)` — delegator is
   * this org, delegate is that person, stewardship SHAPE not mere membership, ERC-1271-live and
   * unrevoked on-chain. An app cannot manufacture that, and presenting someone else's wire does not
   * help, because the wire must name the person its own token proves. So the token answers *who is
   * asking* and the delegation answers *may they act for this org* — unchanged.
   *
   * WHY THIS DIFFERS FROM `ownerOrBridge`, which deliberately refuses a relying app that presents
   * stewardship: there, the principal is a PERSON, so accepting stewardship would let an app holding
   * a person's token pivot to a DIFFERENT principal — an escalation. Here the principal is ALREADY
   * the org, and stewardship is the only authority that ever reaches it. There is nothing to pivot to.
   *
   * RESIDUAL RISK, stated rather than implied: any app the person authorized can act for every org
   * that person stewards, because they all share the person's one identity. Narrowing that needs the
   * per-app scoped grants of §4.1/§4.3, not an audience check — an audience check only decided which
   * ONE app could do it, and made a real client indistinguishable from an attacker.
   */
  private async ownerStewardOrBridge(
    request: Request,
    rawBody: string,
    op: string,
    principal: string,
    session: string,
    stewardship: IncomingDelegation | undefined,
    /**
     * SCOPED ADMISSION. Present for `content.get` / `content.put` on a single ARTIFACT: a data wire
     * covering that exact resource for that exact op is sufficient, without being — or being mistaken
     * for — stewardship. Absent for `content.catalog`, `applications.*` and `invite.put`, so each of
     * those still requires the steward proof.
     */
    scoped?: { readonly wire: IncomingDelegation | undefined; readonly resource: string; readonly op: 'read' | 'write' | 'delete' },
  ): Promise<{ ok: true; scopedGrants?: VaultRecordScopeGrant[] } | { ok: false; reason: string }> {
    if (session) {
      const g = await verifyHomeSession(session, this.env);
      // Home session first, exactly as `ownerOrBridge` orders them. Still not a fallback chain: both
      // branches end in the SAME steward check, and a token that verifies as neither fails closed
      // here rather than reaching the bridge.
      const sa = g.ok
        ? g.sa
        : await verifyRelyingIdToken(session, this.env).then((r) => (r.ok ? r.sa : null));
      if (!sa) return { ok: false, reason: g.ok ? 'no SA in session' : g.error };
      if (sa.toLowerCase() === principal) return { ok: true };
      if (await this.isSteward(principal, sa, stewardship)) return { ok: true };
      // Ordered after stewardship deliberately: a steward is already admitted above, so this branch
      // only ever decides for a caller who is NOT one. Not a fallback — the two proofs are different
      // artifacts answering different questions, and neither is tried because the other failed.
      if (scoped) {
        const r = await this.hasScopedAccess(principal, sa, scoped.wire, scoped.resource, scoped.op);
        // The grants travel with the verdict: index maintenance below has to know what this caller
        // may write, and re-deriving it there would be a second decode that could disagree.
        if (r.ok) return { ok: true, scopedGrants: r.grants };
      }
      return { ok: false, reason: 'only this agent, a steward presenting its stewardship delegation, or a scoped grant covering this record, may reach it' };
    }
    return this.bridgeGate(request, rawBody, op);
  }

  /**
   * The A2A transport for outbound sends.
   *
   * It dials the recipient's own `A2aTaskDO` — the SAME dispatch `/api/a2a` performs after Host
   * resolution, which is what makes this a real A2A send and not a shortcut: the recipient's gate
   * runs `authorizeA2aMessage` in full (allowedTargets, allowedMethods, timestamp window, ERC-1271
   * on the wire, on-chain `isRevoked`, single-use message id) exactly as it would for a stranger.
   *
   * It is a DO stub rather than an HTTPS fetch because a Worker cannot reliably call a hostname on
   * its own Cloudflare account (CF-1042) — the loopback is the deployment's constraint, not a
   * weakening of the check. Nothing here carries a shared secret; the wire is the authority.
   */
  private a2aTransport(): A2aTransport {
    return {
      rpc: async (target, req) => {
        const t = String(target).toLowerCase();
        const stub = this.env.A2A_TASKS.get(this.env.A2A_TASKS.idFromName(t));
        const resp = await stub.fetch(new Request(`https://a2a-task-do/rpc?agent=${t}`, {
          method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(req),
        }));
        return (await resp.json()) as never;
      },
    };
  }

  /** One-at-a-time queues for the directory's shared records (the audit log, the export list). */
  private readonly directoryQueues = new Map<string, Promise<unknown>>();
  private directorySealer: Sealer | null = null;

  /** The directory's sealer (directory-seal.ts): AKCS envelope purpose `operator-directory`, the wrapped data key in
   *  THIS object's storage (no vault grant reaches it). No AKCS config � every seal/open throws: never written unsealed. */
  private sealerFor(principal: string): Sealer {
    if (this.directorySealer) return this.directorySealer;
    const kms = new RemoteAgenticKmsProvider(agenticKmsConfig(this.env as never, { envelopePurpose: SEAL_PURPOSE }));
    this.directorySealer = makeSealer({
      workspace: principal,
      store: {
        get: async () => (await this.state.storage.get<StoredDek>('directory.dek')) ?? undefined,
        put: async (d) => { await this.state.storage.put('directory.dek', d); },
      },
      envelope: {
        generate: async (aadContext) => {
          const g = await kms.generateSessionDataKey({ aadContext });
          return { plaintext: g.plaintextDataKey, wrapped: g.encryptedDataKey, keyId: g.keyId, keyVersion: g.keyVersion };
        },
        unwrap: async (d, aadContext) =>
          kms.decryptSessionDataKey({ encryptedDataKey: d.wrapped, keyId: d.keyId, keyVersion: d.keyVersion, aadContext } as never),
      },
    });
    return this.directorySealer;
  }

  /** What operator-directory-ops.ts needs from this object: identity, on-chain checks, and the vault. */
  private directoryCtx(principal: string): DirectoryCtx {
    return {
      principal,
      now: () => Date.now(),
      newId: () => crypto.randomUUID(),
      verifySession: async (s) => {
        const v = await verifyHomeSession(s, this.env);
        return v.ok ? { ok: true, sa: v.sa, ...(v.principal ? { principal: v.principal } : {}) } : { ok: false, error: v.error };
      },
      isSteward: (org, sa, wire) => this.isSteward(org, sa as Address, wire as unknown as IncomingDelegation | undefined),
      // Signature, time window AND not revoked (security review 2026-10-23, #8): an old or revoked grant cannot be put back.
      grantSignatureOk: async (wire) => this.verifyWire(wire as unknown as IncomingDelegation, wire.delegator, wire.delegate as Address),
      recordScopes: (wire) => {
        try {
          const cav = (wire.caveats ?? []).find((c) => (c.enforcer ?? '').toLowerCase() === VAULT_RECORD_SCOPE_ENFORCER.toLowerCase());
          return cav?.terms ? decodeVaultRecordScopeTerms(cav.terms as Hex).map((g) => ({ resources: [...g.resources], ops: [...g.ops] })) : null;
        } catch { return null; }
      },
      // The account the org's session leaf names in its audience (the interactions grant's delegate): the only one
      // the vault will accept the DO acting through (spec 408). The directory grant must name it.
      expectedDelegate: async () => String((((await this.state.storage.get('state')) ?? {}) as StoredState).grant?.delegate ?? '').toLowerCase(),
      // An expired directory grant reads as "not enabled" (#2): the grant is short-lived, and Admin then offers Enable
      // again so an admin re-signs it.
      getGrant: async () => {
        const g = (((await this.state.storage.get('state')) ?? {}) as StoredState).directoryGrant;
        return g && this.leafWindowLive(g) !== false ? (g as unknown as DirectoryWire) : undefined;
      },
      setGrant: async (wire) => {
        const st = ((await this.state.storage.get('state')) ?? {}) as StoredState;
        st.directoryGrant = wire as unknown as IncomingDelegation;
        await this.state.storage.put('state', st);
      },
      read: async (g, resource) => (await this.vaultFor(g as unknown as IncomingDelegation).read<unknown>({ owner: '', resource }))?.data ?? null,
      readMany: async (g, resources) => {
        const resp = await this.mcpVaultTool(g as unknown as IncomingDelegation, 'get_vault_records', { recordTypes: resources });
        const got = (await resp.json().catch(() => ({}))) as { ok?: boolean; records?: Record<string, unknown>; error?: string };
        if (!resp.ok || got.ok === false || !got.records) throw new Error(`directory read: ${got.error ?? `the vault answered ${resp.status}`}`);
        return got.records;
      },
      write: (g, resource, data) => this.writeDoc(g as unknown as IncomingDelegation, resource, data),
      serial: <T,>(key: string, work: () => Promise<T>): Promise<T> => {
        const next = (this.directoryQueues.get(key) ?? Promise.resolve()).then(work, work);
        this.directoryQueues.set(key, next.catch(() => undefined));
        return next;
      },
      seal: (account, email) => this.sealerFor(principal).seal(account, email),
      open: (account, sealed) => this.sealerFor(principal).open(account, sealed),
    };
  }

  /** Spec 396 — every op runs under a fresh cost counter; the response carries the numbers as headers. */
  async fetch(request: Request): Promise<Response> {
    return countedOp(() => this.handleOp(request));
  }

  private async handleOp(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const parts = url.pathname.split('/').filter(Boolean); // interactions/<principal>/<op>
    const principal = (parts[1] ?? '').toLowerCase();
    let op = parts[2] ?? '';
    if (!/^0x[0-9a-fA-F]{40}$/.test(principal)) return json({ error: 'bad principal' }, 400);
    const rawBody = await request.text();
    let body: Record<string, unknown> = {};
    try { body = JSON.parse(rawBody) as Record<string, unknown>; } catch { /* empty body ok */ }
    // WHERE AN OP'S TIME GOES, on request (`timings: true`): milliseconds from this point to the end of each named
    // stage, returned beside the answer as `ms`. Numbers only — nothing the op read. A caller that waits on a topic
    // read or a post can then say which hop it waited on, instead of "the board was slow".
    const opT0 = Date.now();
    const opMs: Record<string, number> = {};
    const timedOp = <T,>(name: string, p: Promise<T>): Promise<T> => p.finally(() => { opMs[name] = Date.now() - opT0; });
    const withMs = <T extends Record<string, unknown>>(out: T): T => (body.timings === true ? { ...out, ms: { ...opMs, total: Date.now() - opT0 } } : out);

    // ── Grant custody (plane B): the Worker pre-verifies the steward session + delegator match. ──
    if (op === 'grant' && request.method === 'POST') {
      const wire = body.delegation as IncomingDelegation | undefined;
      if (!wire?.signature || wire.delegator.toLowerCase() !== principal) return json({ error: 'delegation with delegator = principal required' }, 400);
      // Verify the wire IS the principal's before storing (junk-overwrite DoS guard): ERC-1271 over
      // the delegation digest against the delegator (approved-hash 0x03 wires validate through the
      // SA's approved-hash branch). Fail-closed: an unverifiable grant is never stored.
      const d: Delegation = { ...wire, salt: BigInt(wire.salt), caveats: wire.caveats.map((c) => ({ enforcer: c.enforcer, terms: c.terms, args: (c.args ?? '0x') as Hex })) } as Delegation;
      const digest = hashDelegation(d, Number(this.env.CHAIN_ID ?? 84532), this.env.DELEGATION_MANAGER as Address);
      if (!(await this.erc1271(wire.delegator as Address, digest, wire.signature as Hex))) {
        return json({ error: 'grant signature failed verification against the delegator' }, 403);
      }
      // NEW-H6 (Phase B): pin the delegate to the configured interactions service SA. `vaultFor` runs every
      // op as requester=grant.delegate, so a grant issued to any OTHER delegate would route the principal's
      // entire vault surface through the wrong delegate. Inert until provisioned (INTERACTIONS_SERVICE_SA
      // unset ⇒ no pin, the pre-Phase-B behavior).
      const expectedInteractionsSa = (this.env.INTERACTIONS_SERVICE_SA ?? '').toLowerCase();
      if (/^0x[0-9a-f]{40}$/.test(expectedInteractionsSa) && wire.delegate.toLowerCase() !== expectedInteractionsSa) {
        return json({ error: 'grant delegate must be the configured interactions service SA (NEW-H6)' }, 403);
      }
      const st = ((await this.state.storage.get('state')) ?? {}) as StoredState;
      st.grant = wire;
      // NEW-C1 — custody the PRINCIPAL-signed DEL-001 session leaf (principal → interactions-session key), if
      // supplied. Verify it ERC-1271 against the principal (== grant delegator) so the DO never bound-mints
      // with a junk leaf; demo-mcp re-checks the binding at enforceBinding. Absent ⇒ server-mint bridge.
      // Route A (spec 423 §2.1) — accept a LADDER (`sessionLeaves`) or a single legacy leaf (`sessionLeaf`). Each
      // rung is verified ERC-1271 against the principal (== grant delegator) before storing, so the DO never signs
      // under a junk leaf; demo-mcp re-checks the binding at enforceBinding. Absent ⇒ server-mint bridge.
      const leavesWire = Array.isArray(body.sessionLeaves) ? (body.sessionLeaves as IncomingDelegation[]) : undefined;
      const single = body.sessionLeaf as IncomingDelegation | undefined;
      const candidates = (leavesWire && leavesWire.length ? leavesWire : single ? [single] : []).filter((l) => l?.signature);
      if (candidates.length) {
        const verified: IncomingDelegation[] = [];
        for (const lw of candidates) {
          if (lw.delegator.toLowerCase() !== wire.delegator.toLowerCase()) {
            return json({ error: 'session leaf delegator must equal the grant delegator (the principal) — NEW-C1' }, 400);
          }
          const ld: Delegation = { ...lw, salt: BigInt(lw.salt), caveats: lw.caveats.map((c) => ({ enforcer: c.enforcer, terms: c.terms, args: (c.args ?? '0x') as Hex })) } as Delegation;
          const ldigest = hashDelegation(ld, Number(this.env.CHAIN_ID ?? 84532), this.env.DELEGATION_MANAGER as Address);
          if (!(await this.erc1271(lw.delegator as Address, ldigest, lw.signature as Hex))) {
            return json({ error: 'session leaf signature failed verification against the principal (NEW-C1)' }, 403);
          }
          verified.push(lw);
        }
        st.sessionLeaf = verified[0];                              // the live-at-enable rung (back-compat readers)
        if (leavesWire) st.sessionLeaves = verified; else delete st.sessionLeaves; // a single-leaf enable clears a stale ladder
      }
      // Ledger row (W3e): hash + delegate + decoded resources — never the wire (bearer secret).
      let resources: string[] = [];
      try {
        const cav = wire.caveats.find((c) => (c.enforcer ?? '').toLowerCase() === VAULT_RECORD_SCOPE_ENFORCER.toLowerCase());
        if (cav?.terms) resources = decodeVaultRecordScopeTerms(cav.terms as Hex).flatMap((g) => g.resources);
      } catch { /* undecodable scopes → empty resources row; the currency gate handles enforcement */ }
      st.ledger = [...(st.ledger ?? []), { hash: digest, delegate: wire.delegate.toLowerCase(), resources, storedAt: new Date().toISOString() }].slice(-50);
      await this.state.storage.put('state', st);
      return json({ ok: true });
    }
    // spec 323 W3 — custody the write-only DELIVERY wire in the DO (verified like /grant). Same
    // ERC-1271-against-delegator junk-guard; the wire never returns to any app.
    if (op === 'grant.delivery.put' && request.method === 'POST') {
      const wire = body.delegation as IncomingDelegation | undefined;
      if (!wire?.signature || wire.delegator.toLowerCase() !== principal) return json({ error: 'delivery delegation with delegator = principal required' }, 400);
      const d: Delegation = { ...wire, salt: BigInt(wire.salt), caveats: wire.caveats.map((c) => ({ enforcer: c.enforcer, terms: c.terms, args: (c.args ?? '0x') as Hex })) } as Delegation;
      const digest = hashDelegation(d, Number(this.env.CHAIN_ID ?? 84532), this.env.DELEGATION_MANAGER as Address);
      if (!(await this.erc1271(wire.delegator as Address, digest, wire.signature as Hex))) return json({ error: 'delivery grant signature failed verification against the delegator' }, 403);
      // NEW-H6 (Phase B): pin the delivery delegate to the configured delivery service SA (inert until provisioned).
      const expectedDeliverySa = (this.env.DELIVERY_SERVICE_SA ?? '').toLowerCase();
      if (/^0x[0-9a-f]{40}$/.test(expectedDeliverySa) && wire.delegate.toLowerCase() !== expectedDeliverySa) {
        return json({ error: 'delivery grant delegate must be the configured delivery service SA (NEW-H6)' }, 403);
      }
      const st = ((await this.state.storage.get('state')) ?? {}) as StoredState;
      st.deliveryGrant = wire;
      st.ledger = [...(st.ledger ?? []), { hash: digest, delegate: wire.delegate.toLowerCase(), resources: ['(delivery:write-only)'], storedAt: new Date().toISOString() }].slice(-50);
      await this.state.storage.put('state', st);
      return json({ ok: true });
    }
    // The OPERATOR DIRECTORY (2026-10-23). Its own admission per op — the person's session proving the email, a
    // steward of the org, or an admin of this operator org — inside operator-directory-ops.ts. Before the session
    // block because none of these ops is the owner acting on their own records.
    if (DIRECTORY_OPS.has(op) && request.method === 'POST') {
      const out = await handleDirectoryOp(this.directoryCtx(principal), op, body);
      return json(out.body, out.status);
    }
    // spec 341 §5.5b — `invite.token` carries its own capability and must reach the grant WITHOUT a
    // session gate. Handled before the session block; the token is checked inside.
    if (op === 'invite.token') {
      const st = ((await this.state.storage.get('state')) ?? {}) as StoredState;
      // THE DELIVERY WIRE, not the interactions grant.
      //
      // `org.invite:*` is in the DELIVERY grant's record scope (`ORG_INVITE_RESOURCE_SCOPE`,
      // read+write) and in NO scope the interactions grant carries. Reading it under `st.grant`
      // was denied at the vault every time, and the denial surfaced as an unhandled throw — a bare
      // 500 from the op that creates email invitations, for an org whose storage was fully enabled.
      //
      // `invite.get`/`invite.put` already use `st.deliveryGrant` for the same record family, and
      // `orgVault` probes `deliveryGranted` before calling here — so this was the one path reaching
      // for the wrong wire, and the probe it sits behind was already checking for the right one.
      const dg = st.deliveryGrant;
      if (!dg) return json({ error: 'no delivery grant — enable storage for this org first' }, 409);
      const token = String(body.token ?? '');
      if (!/^[A-Za-z0-9_-]{24,128}$/.test(token)) return json({ error: 'token required' }, 400);
      const resource = `org.invite:${token}`;
      // A vault refusal is an ANSWER and must arrive as one. Uncaught, it became a 500 with no body,
      // which tells a caller nothing about whether they were denied, throttled, or hit an outage —
      // and the invite path had no other signal to go on.
      try {
        if (body.data !== undefined) {
          await this.writeDoc(dg, resource, body.data);
          return json({ ok: true });
        }
        const rec = await this.vaultFor(dg).read<unknown>({ owner: '', resource });
        return json({ ok: true, record: rec?.data ?? null });
      } catch (e) {
        return json({ error: `invite record unavailable: ${e instanceof Error ? e.message : String(e)}` }, 502);
      }
    }
    if (op === 'status') {
      const st = ((await this.state.storage.get('state')) ?? {}) as StoredState;
      return json({
        ok: true, granted: !!st.grant,
        // `current` must mean "this principal can actually transact", not merely "a grant exists with
        // the right scopes". The stored DEL-001 session leaf names the DO's interactions-session key as
        // its delegate BY ADDRESS, so rotating that key strands every principal: the leaf still points at
        // the old address, the DO signs with the new one, and every vault call fails DEL-001 while status
        // cheerfully reported `current: true` — so the Home's activateInteractionsIfNeeded skipped and
        // nothing ever re-issued. Seen live on the 2026-09-02 AKCS cutover. Including the leaf's delegate
        // here makes a key rotation self-heal on the principal's next sign-in.
        current: !!st.grant && this.grantIsCurrent(st.grant) && await this.sessionLeafMatchesSigner(st) && this.sessionLeafLive(st) !== false && this.sessionLeafAudienceOk(st),
        // The leaf's own window, so a Home can say "your agent's session leaf expired on …" rather than "stale".
        leafLive: this.sessionLeafLive(st),
        // Spec 408 §2.1 — does the leaf carry an audience? A pre-408 leaf reports live+matched but mcp rejects it;
        // surfacing this lets a Home say "re-enable to renew the signing leaf" instead of a bare "auth failed".
        leafAudienceOk: this.sessionLeafAudienceOk(st),
        // WHAT THE GRANT ACTUALLY COVERS. `granted` and `current` both say yes while a write is refused
        // with `record_scope_denied`, because a grant can be present, unstale, and still not name the
        // record someone is trying to write. Reporting the resources makes that answerable instead of
        // inferable — for an operator, and for the person whose Home has to decide whether to re-issue.
        recordScopes: (() => {
          try {
            const cav = (st.grant?.caveats ?? []).find((c) => (c.enforcer ?? '').toLowerCase() === VAULT_RECORD_SCOPE_ENFORCER.toLowerCase());
            return cav?.terms ? [...new Set(decodeVaultRecordScopeTerms(cav.terms as Hex).flatMap((g2) => g2.resources))].sort() : [];
          } catch { return []; }
        })(),
        deliveryGranted: !!st.deliveryGrant,
        // The migration, visible from outside. A ladder whose rungs can only be read by grepping the
        // source is one nobody checks before promoting — and promotion is exactly the decision that
        // needs the evidence in front of it. `divergences` carries outcomes, INCLUDING `equal`: a report
        // showing only differences cannot distinguish agreement from a shadow that never ran, and those
        // two justify opposite decisions.
        gatewayAdoption: GATEWAY_ADOPTION,
        divergences: this.divergences,
      });
    }

    // ── 1-1 inbox residency (spec 322 W3f) — the Home-server channel + in-Worker delivery. ──
    // The Home reaches this principal's mail ONLY here (bridge-HMAC-authenticated, the same SEC-010
    // envelope as the custody bridge); the a2a messaging skills merge deliveries here in-Worker
    // (`internal.deliver` — the public route refuses `internal.*`, so only Worker code reaches it).
    // The standing DELIVERY grant is write-only: it can no longer read anyone's mail.
    if (op === 'inbox.get' || op === 'gateway.inbox.get' || op === 'inbox.put' || op === 'inbox.body.get' || op === 'inbox.body.getMany' || op === 'internal.deliver' || op === 'internal.dm.body.put' || op === 'internal.channels.read' || op === 'internal.channels.post' || op === 'internal.channels.create' || op === 'internal.assistantSkill.get' || op === 'internal.invite.decline' || op === 'internal.library.skillMd' || op === 'internal.coordination.vaultRead' || op === 'internal.coordination.vaultWrite' || op === 'internal.readgrant.list' || op === 'internal.readgrant.wire' || op === 'internal.studygrant.wire' || op === 'internal.profile.merge' || op === 'internal.household.record' || op === 'internal.email.admit' || op === 'internal.coordination.vaultSurvey' || op === 'internal.coordination.vaultQuery' || op === 'internal.inbox.read' || op === 'internal.inbox.post' || op === 'internal.consult.context' || op === 'internal.consult.eligible' || op === 'internal.consult.orgWire' || op === 'internal.session.leaf' || op === 'internal.consult.grant' || op === 'internal.member.current' || op === 'internal.member.recorded' || op === 'internal.member.role' || op === 'internal.member.setRole' || op === 'internal.archetype.grant' || op === 'internal.archetype.hosts' || op === 'internal.library.packages' || op === 'internal.endeavor.request' || op === 'internal.endeavor.proposePlan' || op === 'internal.endeavor.state' || op === 'internal.endeavor.create' || op === 'internal.endeavor.adoptPlan' || op === 'internal.endeavor.satisfyStep' || op === 'internal.endeavor.satisfy' || op === 'internal.endeavor.post' || op === 'internal.applications.append' || op === 'internal.resolution.request' || op === 'internal.resolution.settle' || op === 'internal.resolution.grant' || op === 'internal.resolution.approve' || op === 'internal.resolution.revoke' || op === 'internal.resolution.status' || op === 'internal.resolution.project' || op === 'internal.runtime.wake.put' || op === 'internal.runtime.pairing.claim' || op === 'internal.runtime.pairing.take' || op === 'internal.search.query' || op === 'internal.grants.audit' || op === 'internal.grant.byDigest' || op === 'internal.wire.current' || op === 'internal.op.lookup' || op === 'controlevents.append' || op === 'dm.body.put' || op === 'invite.get' || op === 'invite.put' || op === 'applications.get' || op === 'applications.put' || op === 'content.get' || op === 'content.getMany' || op === 'content.put') {
      // Owner-facing residency ops accept the OWNER's session OR the bridge (spec 323 W4 — a portable
      // Home needs no secret). invite.* are substrate steward/redeem flows → bridge only. internal.*
      // are in-Worker (a2a deliver skill / spec 327 assistant pipeline) → no external gate.
      /** The relying app that called, when one did. Null for the person's own Home. */
      let callerClientId: string | null = null;
      /** Set only when the caller got in on a SCOPED data grant — see the content handler's merge. */
      let scopedGrants: VaultRecordScopeGrant[] | null = null;
      const OWNER_FACING = op === 'inbox.get' || op === 'gateway.inbox.get' || op === 'inbox.put' || op === 'inbox.body.get' || op === 'inbox.body.getMany' || op === 'controlevents.append' || op === 'dm.body.put';
      // spec 341 §5.3 — an ORG's governance docs are steward-facing, not owner-facing: the principal is
      // the org and it has no session. Same verified delegation the messaging rail uses.
      //
      // `content.*` joins them (§5.4). The Home route that drives those ops ALREADY fetched the org's
      // stewardship wire and then authorized the call with the shared secret instead — the authority
      // artifact was obtained and discarded. Now it is the thing that decides.
      const STEWARD_FACING = op === 'applications.get' || op === 'applications.put' || op === 'content.get' || op === 'content.getMany' || op === 'content.put'
        // spec 341 §5.5b — ISSUING an invite is the org acting, so it takes the steward's proof like
        // every other org act. CLAIMING one is not here: it is the invitee's own op (`invite.claim`),
        // and they hold no stewardship by definition.
        || op === 'invite.put';
      if (op.startsWith('internal.')) {
        // ARCH-H2 — the public router refuses internal.*, but the DO must NOT trust that alone.
        // Require the in-Worker marker, which only co-resident DOs can supply. Any other path
        // reaching internal.* fails closed — including one holding the CUSTODY secret, which used to
        // be this same value and no longer is (spec 341 §7).
        if (!isInternalCall(request, this.env)) return json({ error: 'internal op — not authorized' }, 403);
      } else {
        const og = OWNER_FACING ? await this.ownerOrBridge(request, rawBody, op, principal, String(body.session ?? ''), body.stewardship as IncomingDelegation | undefined) : null;
        callerClientId = og?.ok ? (og.clientId ?? null) : null;
        const bg = OWNER_FACING
          ? og!
          : STEWARD_FACING
            ? await this.ownerStewardOrBridge(
                request,
                rawBody,
                op,
                principal,
                String(body.session ?? ''),
                body.stewardship as IncomingDelegation | undefined,
                // CONTENT OPS ONLY. Artifacts by their own scope; the catalog only as a MERGE for a wire
                // that names it (see scopedContentOp and the content handler) — a scoped caller never
                // replaces the org-wide index. `applications.*` and `invite.put` are steward-facing acts
                // of a different sensitivity and stay exactly as they were.
                ((q) => (q ? { ...q, wire: body.scopedAccess as IncomingDelegation | undefined } : undefined))(
                  scopedContentOp(op, String(body.resource ?? ''), body.data),
                ),
              )
            : await this.bridgeGate(request, rawBody, op);
        if (!bg.ok) return json({ error: `unauthorized: ${bg.reason}` }, 401);
        // A caller admitted ONLY by a scoped grant may not replace org-wide state; the content
        // handler merges instead. Absent for a steward, an owner or the bridge — all of whom may.
        // `bg` unions three gate shapes and only one carries grants; narrow explicitly rather than
        // by `in`, which widens to `{}` here and would silently type the merge's input as unknown.
        scopedGrants = (bg as { scopedGrants?: VaultRecordScopeGrant[] }).scopedGrants ?? null;
      }
      const st0 = ((await this.state.storage.get('state')) ?? {}) as StoredState;
      let g = st0.grant;
      if (!g) return json({ error: 'no interactions grant — enable interactions for this agent first' }, 409);
      if (!this.grantIsCurrent(g)) return json({ error: 'interactions grant is stale — re-enable (scope widened this wave)' }, 409);
      // spec 341 §4.3 — WHICH grant this read runs under is decided by WHO the verified caller is, once,
      // before any vault call. A relying app runs under its OWN scoped grant; the person's own control
      // plane runs under the principal's. That is caller-selected, not a fallback: neither is tried
      // after the other fails, and an app with no grant is REFUSED rather than quietly borrowing the
      // broad one — which is the whole point, because borrowing it is what made revocation
      // all-or-nothing (ADR-0013).
      if (callerClientId) {
        const rec = (await this.state.storage.get(READ_GRANT_KEY(callerClientId))) as ReadGrantRecord | undefined;
        if (!rec) {
          return json({ error: 'this app has no read grant — the person authorizes it once, and can revoke it alone', code: 'read_grant_absent', clientId: callerClientId }, 409);
        }
        // Revocation is checked HERE, per read, not at store time: an on-chain revoke must stop the
        // NEXT read rather than one after a cache expires. Fail-closed on an unreadable chain.
        try {
          const revoked = (await this.pub().readContract({ address: this.env.DELEGATION_MANAGER as Address, abi: IS_REVOKED_ABI, functionName: 'isRevoked', args: [rec.hash as Hex] })) as boolean;
          if (revoked) return json({ error: 'this app’s read grant was revoked', code: 'read_grant_revoked', clientId: callerClientId }, 403);
        } catch {
          return json({ error: 'revocation check unavailable — read refused (fail-closed)' }, 503);
        }
        // DOES THIS APP'S GRANT COVER THIS OP? A courtesy check, not the enforcement point: demo-mcp
        // re-enforces server + resource + `ops` per record and is the authority. Doing it here turns a
        // scope mismatch into a refusal that NAMES the missing resource, instead of an opaque
        // `record_scope_denied` from one hop away.
        const need = OP_RESOURCE[op];
        if (need) {
          let covered = false;
          try {
            const scopeCav = (rec.wire.caveats ?? []).find((c) => (c.enforcer ?? '').toLowerCase() === VAULT_RECORD_SCOPE_ENFORCER.toLowerCase());
            const granted = scopeCav?.terms ? decodeVaultRecordScopeTerms(scopeCav.terms as Hex).flatMap((gr) => gr.resources) : [];
            covered = granted.some((r) => (r.endsWith('*') ? need.startsWith(r.slice(0, -1)) : r === need));
          } catch { covered = false; }
          if (!covered) {
            return json({ error: `this app's read grant does not cover ${need}`, code: 'read_grant_scope', clientId: callerClientId, need }, 403);
          }
        }
        g = rec.wire;
      }
      try {
        if (op === 'inbox.get') {
          const doc = await this.readDoc<unknown>(g, INBOX_RESOURCE, null);
          // spec 341 Wave 2a — the read cursor. A caller that presents the revision it already holds
          // gets `unchanged` instead of the document. The vault read above is unavoidable (we must
          // read to digest), so this does not save the round trip; it saves the TRANSFER and, on the
          // caller's side, `hydrateInboxStores` — an O(events) replay it otherwise performs on every
          // single poll. Absent cursor ⇒ always the document (a first-time caller has seen nothing).
          // SHADOW (gateway adoption, rung 2). InteractionsDO's answer above IS the response — the shadow
          // runs after it, cannot change it, and cannot fail the request. Sampled, because this is the
          // hottest path in the app and doubling its vault reads is how a comparison harness takes down
          // the thing it was measuring. See `gateway-adoption.ts`.
          if (gatewayStage('inbox.get', this.env) === 'shadow') this.shadowInboxGet(g, doc);
          const revision = doc === null ? null : await inboxRevision(doc as InboxDataV1);
          const since = typeof body.sinceRev === 'string' ? body.sinceRev : undefined;
          if (revision !== null && since && since === revision) {
            return json({ ok: true, unchanged: true, revision });
          }
          return json({ ok: true, doc, ...(revision ? { revision } : {}) });
        }
        // THE MOUNT (ADR-0055 amendment) — the first live traffic served by `PrincipalGatewayDO`.
        //
        // Deliberately the same read as `inbox.get` directly above, over the same vault record, returning
        // the same shape. Mirroring an existing op rather than adding a new one is what makes this
        // checkable: the two planes read one record, so a difference in what they return is a defect and
        // not a design question. It is also what makes it disposable — deleting this block leaves the
        // serving plane exactly as it was, with no migration tag and no addressable object stranded.
        //
        // WHAT MOVED: nothing. The record is in the owner's MCP vault before this op and after it. The
        // gateway supplies its serving-plane machinery (the cached verdict, the single-use request id)
        // and reaches the record through the INJECTED vault, which is the whole claim being tested here.
        if (op === 'gateway.inbox.get') {
          let doc: unknown;
          try { doc = await this.gatewayReadInbox(g, principal); }
          catch (e) { return json({ error: e instanceof Error ? e.message : String(e), code: 'gateway_refused' }, 403); }
          const revision = doc === null ? null : await inboxRevision(doc as InboxDataV1);
          const since = typeof body.sinceRev === 'string' ? body.sinceRev : undefined;
          if (revision !== null && since && since === revision) return json({ ok: true, unchanged: true, revision, servedBy: 'gateway' });
          return json({ ok: true, doc, ...(revision ? { revision } : {}), servedBy: 'gateway' });
        }
        if (op === 'inbox.put') {
          if (body.doc === undefined) return json({ error: 'doc required' }, 400);
          await this.writeDoc(g, INBOX_RESOURCE, body.doc);
          // spec 328 §3 — post-commit assistant scan (the HOME ingress: the two-party send/deliver
          // orchestration lands here as a whole-doc write). Fire-and-forget; the seen-ledger diff
          // finds what's new. Never affects this response.
          const scanEnvs = (body.doc as { envelopes?: MessageEnvelopeV1[] } | null)?.envelopes;
          if (Array.isArray(scanEnvs)) this.queueInboxAssistantScan(principal, scanEnvs);
          return json({ ok: true });
        }
        if (op === 'applications.get') {
          const doc = await this.readDoc<unknown>(g, APPLICATIONS_RESOURCE, { applications: [] });
          return json({ ok: true, doc });
        }
        if (op === 'applications.put') {
          if (body.doc === undefined) return json({ error: 'doc required' }, 400);
          // DIAGNOSTIC (apply-chain): the other writer of this doc. `dropOrgApplication` is the only
          // caller and it should run ONLY after an approve/reject — so a put arriving with an empty list
          // when nobody decided anything is the thing worth catching. Logs the caller so an unexpected
          // one names itself rather than being inferred.
          const putRows = Array.isArray((body.doc as { applications?: unknown[] })?.applications)
            ? ((body.doc as { applications: unknown[] }).applications).length : -1;
          console.log(`[apply-put] org=${principal} rows=${putRows} client=${callerClientId ?? 'home'}`);
          await this.writeDoc(g, APPLICATIONS_RESOURCE, body.doc);
          return json({ ok: true });
        }
        if (op === 'inbox.body.get') {
          // dm-namespace ONLY — the bridge cannot be aimed at arbitrary vault records (the grant's
          // record scope enforces the same bound at the vault; this is the belt to that suspender).
          const resource = String(body.resource ?? '');
          if (!resource.startsWith(DM_BODY_PREFIX)) return json({ error: 'dm body resources only' }, 400);
          const r = await this.vaultFor(g).read<unknown>({ owner: '', resource });
          return json({ ok: true, record: r?.data ?? null });
        }
        if (op === 'inbox.body.getMany') {
          // BATCHED DM body read (perf, 2026-10-03) — ONE `get_vault_records` for a whole thread's bodies
          // instead of one `get_vault_record` per message. The live failure: opening a 75-message thread
          // fired 75 vault reads, saturated the principal's stage-2 verified-call budget (120/60s), and
          // every body came back "auth failed" (the throttle's opaque reject) → "content in vault…". Reuses
          // `readTopicBodies` — the same batched, per-envelope hash-verified read the channels use — and
          // stays dm-namespace only (the grant's record scope is the real bound; this is the belt).
          const raw = Array.isArray(body.envelopes) ? (body.envelopes as AnyMessageEnvelope[]) : [];
          const envelopes = raw.filter((e) => typeof e?.body?.resource === 'string' && e.body.resource.startsWith(DM_BODY_PREFIX));
          if (envelopes.length === 0) return json({ ok: true, bodies: {} });
          const bodies = await this.readTopicBodies(g, envelopes);
          return json({ ok: true, bodies });
        }
        // spec 327 §4b / spec 334 §6 — the org playbook, read for the COORDINATION turns (plan-draft
        // + work), which have no board channel to carry it the way internal.channels.read does. Same
        // org-level doc as the discussion assistant, so ONE steward-authored SKILL.md governs both the
        // @ask assistant and the endeavor agent. Absent ⇒ no markdown (the turn keeps its built-in
        // contract, unchanged). Read-only, in-Worker marker only.
        // "NOT INTERESTED" — an emailed invitation, declined by the person who holds its token (spec 315;
        // 365 rule 1 stands: this is not an act of authority, it is a NO, and it changes nothing but the
        // invitation's own status). Token-bound: only a pending record moves, and only to `declined`; a
        // redeemed one is never un-joined by a link, and an unknown token learns nothing. The agent-keyed
        // twin (`org.invite:agent:<predicted>`) is marked too, so the roster's invitation row says so.
        if (op === 'internal.invite.decline') {
          const token = String(body.token ?? '');
          if (!/^[a-f0-9]{40,80}$/.test(token)) return json({ error: 'invalid token' }, 400);
          const dg = st0.deliveryGrant;
          if (!dg) return json({ error: 'no delivery grant — this organization keeps no invitations' }, 409);
          const rec = ((await this.vaultFor(dg).read<Record<string, unknown>>({ owner: '', resource: `org.invite:${token}` }))?.data ?? null) as Record<string, unknown> | null;
          if (!rec) return json({ ok: false, error: 'no such invitation' }, 404);
          if (rec.status === 'redeemed') return json({ ok: true, status: 'redeemed', changed: false });
          if (rec.status === 'declined') return json({ ok: true, status: 'declined', changed: false });
          const declinedAt = Date.now();
          await this.vaultFor(dg).write({ owner: '', resource: `org.invite:${token}`, data: { ...rec, status: 'declined', declinedAt } });
          const delegate = String((rec.memberAccessDelegation as { delegate?: string } | undefined)?.delegate ?? '').toLowerCase();
          if (/^0x[0-9a-f]{40}$/.test(delegate)) {
            const twin = ((await this.vaultFor(dg).read<Record<string, unknown>>({ owner: '', resource: `org.invite:agent:${delegate}` }))?.data ?? null) as Record<string, unknown> | null;
            if (twin && twin.status !== 'redeemed') await this.vaultFor(dg).write({ owner: '', resource: `org.invite:agent:${delegate}`, data: { ...twin, status: 'declined', declinedAt } });
          }
          await buildAuditSink(this.env).write({ id: crypto.randomUUID(), timestamp: new Date(declinedAt).toISOString(), action: 'interactions.invite.declined', outcome: 'success', actor: { type: 'service', id: principal }, subject: { type: 'invitation', id: token.slice(0, 8) } });
          if (st0.grant) await this.postWelcome(st0.grant, principal, `🙅 ${/^0x[0-9a-f]{40}$/.test(delegate) ? await this.boardNameFor(st0.grant, delegate) : 'An invitee'} is not interested in joining.`);
          return json({ ok: true, status: 'declined', changed: true, ...(typeof rec.invitedBy === 'string' ? { invitedBy: rec.invitedBy } : {}), ...(typeof rec.orgName === 'string' ? { orgName: rec.orgName } : {}) });
        }
        if (op === 'internal.assistantSkill.get') {
          const skill = await this.readDoc<AssistantSkillDocV1 | null>(g, ASSISTANT_SKILL_RESOURCE, null);
          return json({ ok: true, ...(skill?.markdown ? { skillMarkdown: skill.markdown } : {}) });
        }
        // spec 334 §6 — the coordination agent reads ONE of the principal's OWN app records by
        // recordType, owner-self, through the interactions grant `g` (whose scope now carries the
        // additive read-only APP_COORDINATION_READ_SCOPES, minted at the Home). recordType is opaque
        // here — the platform never names it. A grant that predates those scopes denies per-record at
        // demo-mcp (`record_scope_denied`); we surface that as needsEnable so the caller can prompt the
        // steward to re-enable storage at their Home (the same additive-scope re-enable as coordination.*).
        // ── spec 360 E5 — WRITE ONE DECLARED-EFFECT ARTIFACT into this principal's own vault.
        //
        // The receipt of a payment is held by BOTH parties, and the payee's copy cannot be written by the
        // payer: she has no authority over his vault and must not. So it is admitted the way mail is
        // (`messaging.deliver`, `org.apply`): the caller carries no write authority at all, and the
        // PRINCIPAL'S OWN grant performs the write inside the principal's own DO.
        //
        // ALLOWLISTED BY RECORD TYPE, hard. The bound is spec 360 §1's disclosure rule made structural:
        // an internal caller may deposit a receipt of an act this principal was party to, and nothing
        // else. Without this the op would be "any in-Worker code may write any record to anyone", which
        // is a far larger thing than the feature it exists for.
        if (op === 'internal.coordination.vaultWrite') {
          const recordType = String(body.recordType ?? '').trim();
          if (!EFFECT_WRITABLE_RECORDS.some((p) => recordType.startsWith(p))) {
            return json({ ok: false, error: `internal.coordination.vaultWrite may not write "${recordType}" — declared-effect artifacts only` }, 403);
          }
          if (body.record === undefined) return json({ ok: false, error: 'record required' }, 400);
          // A COACH SERVICE KEEPS NOTHING OF A CLIENT'S. The person's study records (hand, style, read, note)
          // live in the PERSON's vault and the service reaches them under her grant; a service that filed her
          // hands in its own cabinet would keep them after she fired it — the one design mistake the
          // arrangement exists to make impossible. Refused here, on the principal, whoever asked.
          if ((/^cardroom\.(?:[a-z0-9-]+\.)?(hand|hands:.*|style|read|note)$/.test(recordType) || recordType === 'cardroom.profile') && (await this.principalIsService(principal))) {
            return json({ ok: false, error: `a service keeps no "${recordType}" of its own — a client's study records live in the client's vault, under the client's grant` }, 403);
          }
          try {
            await this.writeDoc(g, recordType, body.record);
            await this.recordOperation(body, 'write', recordType); // spec 410 §3 — so a retry finds this write before writing again
            return json({ ok: true, recordType });
          } catch (e) {
            const msg = e instanceof Error ? e.message : String(e);
            // A scope-denied write is a STALE GRANT, not a failure of the payment that produced it.
            // WHAT "NEEDS ENABLING" LOOKS LIKE FROM HERE. A scope denial is one shape; the other is an
            // agent whose interactions plane was never provisioned at all — its vault has no grant, so
            // the MCP hop fails to AUTHENTICATE rather than to authorize ("auth failed"). Both are the
            // same permanent, actionable state: a steward turns storage on once. Reporting the second as
            // transient sent people to "try again later" for something that will never come right on its
            // own — which is what a team chartered through the Ask looked like, because that flow does
            // not provision the planes the Home's org-create does.
            const needsEnable = /record_scope_denied|scope|auth failed|no grant|grant_absent|not enabled/i.test(msg);
            return json({ ok: false, recordType, ...(needsEnable ? { needsEnable: true } : {}), error: msg });
          }
        }

        // ── AN EMAIL ARRIVED (spec 365) ───────────────────────────────────────────────────────
        //
        // It becomes a MESSAGE in this person's own inbox and nothing else. There is no branch here that
        // reads the body for instructions, and there will not be one: an email is not authority (spec
        // 309 §4.2), and everything a person can do from the resulting thread they do from their own
        // surface under their own mandate.
        //
        // WHO IT IS FROM, honestly. The envelope's `from` is the GATEWAY agent that delivered it —
        // because that is what actually did — and the human's address rides as a claim on a contextRef
        // and in the body. An envelope that named the address as its sender would be asserting an
        // identity nobody verified, which is the whole of email fraud.
        //
        // ONE THREAD PER CORRESPONDENT: the conversation id is derived from the ADDRESS, so mail from
        // one person gathers in one place instead of every email landing in a single "email" thread.
        if (op === 'internal.email.admit') {
          const claimedFrom = String(body.claimedFrom ?? '').trim().toLowerCase();
          const bodyText = String(body.bodyText ?? '').trim();
          const gateway = String(body.gateway ?? '').toLowerCase();
          if (!claimedFrom || !bodyText || !/^0x[0-9a-f]{40}$/.test(gateway)) {
            return json({ ok: false, error: 'claimedFrom, bodyText and gateway are required' }, 400);
          }
          if (!g) return json({ ok: false, needsEnable: true, error: 'interactions storage not enabled' });
          const chainIdEmail = Number(this.env.CHAIN_ID ?? 84532);
          const digestOf = async (v: string): Promise<string> => {
            const bytes = new TextEncoder().encode(v);
            const hash = await crypto.subtle.digest('SHA-256', bytes);
            return [...new Uint8Array(hash)].slice(0, 12).map((b) => b.toString(16).padStart(2, '0')).join('');
          };
          // ONE THREAD PER CORRESPONDENT, BOTH DIRECTIONS. The id is derived from the address, so what
          // this person sent to somebody and what came back sit together — two mailboxes for one
          // relationship is how half a conversation goes missing.
          const conversationId = `conv_email_${await digestOf(claimedFrom)}`;
          const outbound = body.direction === 'out';
          const emailAudit = buildAuditSink(this.env);
          return this.serialize(async () => {
            const built = await buildOutboundMessage({
              // OUTBOUND is FROM this person (they wrote it); INBOUND is from the GATEWAY that delivered
              // it, never from the address — an envelope naming an unverified address as its sender
              // would be asserting an identity nobody checked.
              from: caip10(chainIdEmail, (outbound ? principal : gateway) as Address) as never,
              to: caip10(chainIdEmail, (outbound ? gateway : principal) as Address) as never,
              bodyText,
              ...(body.subject ? { title: String(body.subject) } : {}),
              conversationId,
              // The address, as a POINTER a surface can render — labelled a claim, never an identity.
              contextRefs: [{ kind: outbound ? 'email-to' : 'email-from', id: claimedFrom, label: claimedFrom }],
            });
            if (!built.ok) return json({ ok: false, error: built.error }, 400);
            const { envelope, bodyBytes } = built;
            let bin = '';
            for (const b of bodyBytes) bin += String.fromCharCode(b);
            // PARSE IN MEMORY, STORE IN THE VAULT (spec 362 §6.2 / ADR-0055): the body goes to the
            // owner's vault under their own grant, and nothing about this mail is kept DO-local.
            await this.vaultFor(g).write({ owner: '', resource: envelope.body.resource, data: { b64: btoa(bin), contentType: 'text/plain', bodyHash: envelope.bodyHash }, classification: 'internal' } as never);
            const doc = (await this.readDoc<Record<string, unknown>>(g, INBOX_RESOURCE, null as never)) ?? { version: 1, envelopes: [], events: [] };
            const envs = (doc.envelopes as AnyMessageEnvelope[] | undefined) ?? [];
            // The same message delivered twice is one message: providers retry, and a duplicated thread
            // entry is a person reading the same mail again and wondering what changed.
            if (body.messageId && envs.some((e) => (e as { emailMessageId?: string }).emailMessageId === String(body.messageId))) {
              return json({ ok: true, duplicate: true, conversationId });
            }
            doc.envelopes = [...envs, { ...envelope, ...(body.messageId ? { emailMessageId: String(body.messageId) } : {}) }];
            doc.events = [...((doc.events as unknown[] | undefined) ?? []), { version: 'ap.message.event.v1', messageId: envelope.id, actor: envelope.from, eventType: outbound ? 'sent' : 'delivered', at: envelope.createdAt }];
            await this.writeDoc(g, INBOX_RESOURCE, doc);
            await emailAudit.write({ id: crypto.randomUUID(), timestamp: envelope.createdAt, action: 'interactions.email.admit', outcome: 'success', actor: { type: 'service', id: gateway }, subject: { type: 'message', id: envelope.id } }).catch(() => undefined);
            return json({ ok: true, messageId: envelope.id, conversationId });
          });
        }

        // ── WHO THEY LIVE WITH (spec 363 W4) ──────────────────────────────────────────────────
        //
        // ONE MEMBER AT A TIME, MERGED BY AGENT. "Sarah is my daughter" says one thing about a record
        // that may hold four people; writing the document would delete the rest, which is the same data
        // loss the profile merge exists to prevent.
        //
        // PRIVATE TIER, and this op is the only writer. The record never leaves the vault: no projection
        // to the directory, no row in the KB, no copy in the Home's storage. Who lives with whom is not
        // derivable from chain state, so ADR-0040 forbids it reaching the public read tier at all.
        //
        // IT GRANTS NOTHING. A `guardian` role here does not let anyone act for a dependent; that is a
        // delegation the dependent's custodian issues. No gate reads this record.
        if (op === 'internal.household.record') {
          const member = String(body.member ?? '').trim().toLowerCase();
          if (!/^0x[0-9a-f]{40}$/.test(member)) return json({ ok: false, error: 'member must be an agent address' }, 400);
          if (member === principal) return json({ ok: false, error: 'you are already in your own household — record the people you live WITH' }, 400);
          if (!g) return json({ ok: false, needsEnable: true, error: 'interactions storage not enabled' });
          // THE ONTOLOGY'S OWN WORDS. `kinTermFor` reads the T-box's prefLabels and altLabels, so
          // "daughter" is `aphh:child` here and in the resolver — it was recorded as `other` in one and
          // matched as `child` in the other while each kept its own set.
          const role = householdRoleFor(String(body.role ?? ''));
          const kinRaw = String(body.kin ?? '').trim().toLowerCase();
          // A word the vocabulary does not name is kept VERBATIM as `otherKin`'s label rather than
          // squeezed into the nearest term — the T-box says why the list is deliberately short.
          const kin = kinRaw ? (kinTermFor(kinRaw) ?? 'other') : undefined;
          const kinLabel = kin === 'other' ? kinRaw.slice(0, 40) : undefined;
          const label = String(body.label ?? '').trim().slice(0, 80);
          const remove = body.remove === true;
          const householdAudit = buildAuditSink(this.env);
          // WHICH HOUSEHOLD. A person can belong to more than one — a child between two homes, someone
          // with a family house and a city flat, a carer who lives part of the week elsewhere — and the
          // T-box always said so (`memberOfHousehold` ranges over householdS). The record did not: one
          // flat list meant one household, and adding the second person's home overwrote the first.
          //
          // The legacy shape (`{ members: [...] }` at the root) reads as the household named "home", so
          // nothing already recorded is lost or needs migrating.
          const householdName = String(body.household ?? '').trim().slice(0, 60) || 'home';
          return this.serialize(async () => {
            const doc = (await this.readDoc<{ v?: number; members?: Array<Record<string, unknown>>; households?: Array<Record<string, unknown>> }>(g, 'household.data', null as never)) ?? { v: 1 };
            const households = Array.isArray(doc.households) ? [...doc.households]
              : Array.isArray(doc.members) ? [{ id: 'home', label: 'home', members: doc.members }]
              : [];
            const key = householdName.toLowerCase();
            const at = households.findIndex((h) => String(h.id ?? h.label ?? '').toLowerCase() === key);
            const current = at >= 0 ? households[at]! : { id: key, label: householdName, members: [] as Array<Record<string, unknown>> };
            const rows = ((current.members as Array<Record<string, unknown>>) ?? []).filter((m) => String(m.agent ?? '').toLowerCase() !== member);
            if (!remove) {
              const prior = (((current.members as Array<Record<string, unknown>>) ?? []).find((m) => String(m.agent ?? '').toLowerCase() === member)) ?? {};
              rows.push({
                ...prior, agent: member, role,
                ...(kin ? { kin } : {}), ...(kinLabel ? { kinLabel } : {}),
                ...(label ? { label } : (prior.label ? { label: prior.label } : {})),
                since: prior.since ?? new Date().toISOString(),
              });
            }
            const next = { ...current, id: current.id ?? key, label: current.label ?? householdName, members: rows };
            if (at >= 0) households[at] = next; else households.push(next);
            // A household nobody is in is not a household — it is a name somebody typed once.
            const kept = households.filter((h) => ((h.members as unknown[]) ?? []).length > 0);
            const members = rows;
            await this.writeDoc(g, 'household.data', { v: 1, households: kept });
            await householdAudit.write({ id: crypto.randomUUID(), timestamp: new Date().toISOString(), action: 'interactions.household.record', outcome: 'success', actor: { type: 'user', id: principal }, subject: { type: 'record', id: 'household.data' } }).catch(() => undefined);
            return json({ ok: true, member, household: householdName, ...(remove ? { removed: true } : { role, ...(kin ? { kin } : {}) }), count: members.length, households: kept.length });
          });
        }

        // ── THE PERSON'S OWN CONTACT PROFILE, MERGED (spec 323 W2 record `impact-profile`) ──
        //
        // MERGE, NEVER REPLACE. "My email is x@y.z" says one thing about a record that holds several,
        // and a whole-document write would silently delete the phone number and address the person
        // never mentioned. A partial update that erases what it did not name is data loss wearing the
        // clothes of an edit.
        //
        // ONLY THE FIELDS THIS RECORD IS FOR. The allowlist is the shape (`ImpactContactProfile`): an
        // op that accepted arbitrary keys would be a general vault-write path with a friendly name.
        // PII, and the person's OWN: the DO is addressed at their SA and reachable only in-Worker,
        // which is the same footing every other internal read here stands on.
        if (op === 'internal.profile.merge') {
          // THE ALLOW-LIST IS THE RECORD'S SHAPE, read from the ontology's one field list (spec 371 §2.2) —
          // the same list the Ask's edit tool and the contract derive from, so the three cannot disagree.
          const ALLOWED = new Set(CONTACT_FIELD_ARGS);
          const patch = (body.fields ?? {}) as Record<string, unknown>;
          const clean: Record<string, string> = {};
          const refused: string[] = [];
          for (const [k, v] of Object.entries(patch)) {
            if (!ALLOWED.has(k)) { refused.push(k); continue; }
            const value = String(v ?? '').trim();
            if (value) clean[k] = value.slice(0, 200);
          }
          if (!Object.keys(clean).length) {
            return json({ ok: false, error: refused.length ? `nothing to change — this record does not hold ${refused.join(', ')}` : 'no fields given' }, 400);
          }
          if (!g) return json({ ok: false, needsEnable: true, error: 'interactions storage not enabled' });
          // The sink is built HERE: `audit` in the enclosing scope is declared further down, and reaching
          // it from up here threw "Cannot access 'audit' before initialization" AFTER the record had been
          // written — an op that both succeeded and reported failure, which is the worst of both.
          const profileAudit = buildAuditSink(this.env);
          return this.serialize(async () => {
            // THE RECORD'S OWN SHAPE, which is `{ v, contact: {...}, attestations }` — the one the Home's
            // profile form writes. Merging these fields at the TOP level instead produced a second shape
            // inside one record: the conversation's edits and the form's edits would each look fine and
            // read each other as empty. One record, one shape (spec 356's binding rule applied where the
            // record is actually written).
            const current = (await this.readDoc<Record<string, unknown>>(g, 'impact-profile', null as never)) ?? {};
            const prior = (current.contact ?? {}) as Record<string, unknown>;
            // Location fields land NESTED, as the Home's form writes them (`contact.location.*` with the
            // precision the filled fields imply), and the legacy aliases `city`/`country` follow — one
            // record, one shape, whichever door the edit came through.
            const scalar: Record<string, string> = {};
            const loc: Record<string, string> = { ...((prior.location ?? {}) as Record<string, string>) };
            let touchedLocation = false;
            for (const [k, v] of Object.entries(clean)) {
              const f = contactField(k);
              if (f?.location) { loc[f.path.split('.').pop()!] = v; touchedLocation = true; }
              else scalar[k] = v;
            }
            const contact: Record<string, unknown> = { ...prior, ...scalar };
            if (touchedLocation) {
              const country = loc.country || String(prior.country ?? '');
              const location: Record<string, string> = { ...loc, ...(country ? { country } : {}), precision: precisionOf(loc) };
              contact.location = location;
              if (location.locality) contact.city = location.locality;
              if (country) contact.country = country;
            }
            const next = { ...current, v: 1, contact };
            await this.writeDoc(g, 'impact-profile', next);
            await profileAudit.write({ id: crypto.randomUUID(), timestamp: new Date().toISOString(), action: 'interactions.profile.merge', outcome: 'success', actor: { type: 'user', id: principal }, subject: { type: 'record', id: 'impact-profile' } }).catch(() => undefined);
            // What CHANGED, so a reply can say it without reading the record back out — and the refused
            // keys, because a field this record does not hold is a fact the person should hear.
            return json({ ok: true, changed: Object.keys(clean), ...(refused.length ? { refused } : {}) });
          });
        }

        // ── WHO CAN READ MY RECORDS, and the grant that says so (spec 341 §4.3, read by the Ask) ──
        //
        // The person's own audit of their own apps, addressed at their OWN DO and reachable only
        // in-Worker. It answers for THIS principal and no other — the caller cannot name a subject,
        // because the URL already did and the Ask only ever addresses the session it verified.
        //
        // `revoked` is the ON-CHAIN answer, as the session-facing list already insists: a person
        // auditing access needs to see that a revoke landed, and an unreadable chain reports revoked
        // (the conservative answer for a question whose purpose is spotting access you did not intend).
        // Spec 400 W2 (B4) — EVERY GRANT THIS AGENT ISSUED that its object can enumerate, for the grants screen: app
        // read grants (Home MCP connections among them), member access delegations (an organization's roster),
        // contacts (a person's), standing grants to runtimes, the study grant to a coach. Each row: who holds it,
        // what it permits, its digest, when, and whether the chain says it is revoked. A list; never the wires.
        if (op === 'internal.grants.audit') {
          // Spec 410 §1.2 — `signed` says what a credential ROTATION does with each wire: an approved-digest wire
          // is re-approved as-is under the new epoch; a key-signed one is re-issued (its key is being retired).
          const rows: Array<{ kind: string; holder: string; holderName?: string; what: string; digest: string; issuedAt?: string; revoked: boolean; source: string; signed: 'approved-digest' | 'key' }> = [];
          const revokedOf = async (digest: string): Promise<boolean> => {
            try { return (await this.pub().readContract({ address: this.env.DELEGATION_MANAGER as Address, abi: IS_REVOKED_ABI, functionName: 'isRevoked', args: [digest as Hex] })) as boolean; } catch { return true; }
          };
          const signedOf = (w: { signature?: string } | undefined): 'approved-digest' | 'key' => (String(w?.signature ?? '').toLowerCase() === '0x03' ? 'approved-digest' : 'key');
          const hashOf = (w: IncomingDelegation): string => hashDelegation({ ...w, salt: BigInt(String(w.salt)), caveats: w.caveats.map((c) => ({ enforcer: c.enforcer, terms: c.terms, args: (c.args ?? '0x') as Hex })) } as Delegation, Number(this.env.CHAIN_ID ?? 84532), this.env.DELEGATION_MANAGER as Address);
          for (const [, v] of await this.state.storage.list({ prefix: READ_GRANT_KEY('') })) {
            const rec = v as ReadGrantRecord;
            rows.push({ kind: 'app', holder: rec.clientId, what: 'reads the records the grant scopes', digest: rec.hash, issuedAt: rec.storedAt, revoked: await revokedOf(rec.hash), source: 'read.grant', signed: signedOf(rec.wire) });
          }
          for (const [, v] of await this.state.storage.list({ prefix: STANDING_GRANT_KEY('') })) {
            const rec = v as StandingGrantRecord;
            rows.push({ kind: 'runtime', holder: rec.holder, ...(rec.holderName ? { holderName: rec.holderName } : {}), what: `${rec.capabilities.join(', ')}${rec.locations.length ? ` to ${rec.locations.length} recipient(s)` : ' to anyone'} until ${new Date(rec.validUntil * 1000).toISOString().slice(0, 10)}`, digest: rec.hash, issuedAt: rec.storedAt, revoked: await revokedOf(rec.hash), source: 'standing.grant', signed: signedOf(rec.wire) });
          }
          const study = await this.state.storage.list({ prefix: STUDY_GRANT_KEY('') });
          for (const [k, v] of study) {
            const rec = v as { wire?: IncomingDelegation; hash?: string; storedAt?: string; delegate?: string };
            if (rec.hash) rows.push({ kind: 'coach', holder: rec.delegate ?? rec.wire?.delegate ?? '', holderName: k.slice(STUDY_GRANT_KEY('').length), what: 'reads the study records; appends notes', digest: rec.hash, ...(rec.storedAt ? { issuedAt: rec.storedAt } : {}), revoked: await revokedOf(rec.hash), source: 'study.grant', signed: signedOf(rec.wire) });
          }
          // Spec 410 §1.2 — THE PLANE WIRES this object custodies for its principal (onboarding's batch): the
          // interactions grant, its session leaf, the inbox-delivery grant, the messaging wire. All approved-digest;
          // all void the moment a credential is retired, so a rotation must re-approve every one of them.
          const plane: Array<[IncomingDelegation | undefined, string, string]> = [
            [st0.grant, 'interactions grant — lets this agent read and write your records', 'plane.interactions'],
            [st0.sessionLeaf, 'session leaf — lets this agent act under its session key', 'plane.session'],
            [st0.deliveryGrant, 'inbox delivery — lets the delivery service write to your inbox', 'plane.delivery'],
          ];
          const msg = (await this.state.storage.get(MESSAGING_WIRE_KEY)) as MessagingWireRecord | undefined;
          if (msg?.wire) plane.push([msg.wire, 'messaging wire — lets your agent send as you', 'plane.messaging']);
          if (msg?.transport) plane.push([msg.transport, 'messaging transport — the delivery leg of the messaging wire', 'plane.messaging.transport']);
          for (const [w, what, source] of plane) {
            if (!w?.delegator || w.delegator.toLowerCase() !== principal) continue;
            const digest = hashOf(w);
            rows.push({ kind: 'plane', holder: w.delegate.toLowerCase(), what, digest, revoked: await revokedOf(digest), source, signed: signedOf(w) });
          }
          // Vault-resident families (the survey names them; the records decode): members and contacts.
          const survey = await this.mcpVaultTool(g, 'list_vault_record', {}).then((r) => r.json()).catch(() => ({})) as { records?: Array<{ record_type: string }> };
          const keys = (survey.records ?? []).map((r) => r.record_type).filter((k) => k.startsWith('org.invite:agent:') || k.startsWith('contact:'));
          if (keys.length) {
            const got = await this.mcpVaultTool(g, 'get_vault_records', { recordTypes: keys.slice(0, 200) }).then((r) => r.json()).catch(() => ({})) as { records?: Record<string, unknown> };
            for (const [k, v] of Object.entries(got.records ?? {})) {
              const rec = v as { delegation?: IncomingDelegation; grantDigest?: string; status?: string; role?: string; createdAt?: number; contact?: string };
              const wire = rec.delegation; if (!wire) continue;
              const digest = rec.grantDigest ?? hashDelegation({ ...wire, salt: BigInt(String(wire.salt)), caveats: wire.caveats.map((c) => ({ enforcer: c.enforcer, terms: c.terms, args: (c.args ?? '0x') as Hex })) } as Delegation, Number(this.env.CHAIN_ID ?? 84532), this.env.DELEGATION_MANAGER as Address);
              const member = k.startsWith('org.invite:agent:');
              if (member && rec.status === 'removed') continue;
              rows.push({ kind: member ? 'member' : 'contact', holder: (member ? k.slice('org.invite:agent:'.length) : String(rec.contact ?? wire.delegate)).toLowerCase(), what: member ? `member access${rec.role ? ` (${rec.role})` : ''}${rec.status ? ` · ${rec.status}` : ''}` : `contact (${rec.role ?? 'contact'})${rec.status === 'removed' ? ' · removed' : ''}`, digest, ...(rec.createdAt ? { issuedAt: new Date(rec.createdAt).toISOString() } : {}), revoked: rec.status === 'removed' ? true : await revokedOf(digest), source: k, signed: signedOf(wire) });
            }
          }
          return json({ ok: true, grants: rows });
        }
        // Spec 410 §3 — DID THIS OPERATION ALREADY HAPPEN HERE? The reconcile's read; `found: null` is absent.
        if (op === 'internal.op.lookup') {
          const opId = String(body.operationId ?? '').trim();
          if (!opId) return json({ error: 'operationId required' }, 400);
          const rec = (await this.state.storage.get(OP_LEDGER_KEY(opId))) as OpLedgerRecord | undefined;
          // An expired row is ABSENT — and deleted now — with the retention said, so a caller can tell the two apart.
          if (rec && opLedgerExpired(rec, Date.now())) { await this.state.storage.delete(OP_LEDGER_KEY(opId)); return json({ ok: true, found: null, retentionDays: OP_LEDGER_RETENTION_DAYS, expired: true }); }
          return json({ ok: true, found: rec ?? null, retentionDays: OP_LEDGER_RETENTION_DAYS });
        }
        // Spec 410 §1.2 step 4 — THE HEAD OF A WIRE'S LINEAGE, for the delegate that holds a stale copy. Reads this
        // principal's `delegation.lineage:*` records (the vault, ADR-0055), walks `supersedes` to the head, and
        // answers ONLY the delegate the wire names. `unknown` when no record mentions the hash: the router then
        // reports the original as current or gone from what the chain says about it.
        if (op === 'internal.wire.current') {
          const want = String(body.hash ?? '').toLowerCase();
          const delegate = String(body.delegate ?? '').toLowerCase();
          if (!/^0x[0-9a-f]{64}$/.test(want) || !/^0x[0-9a-f]{40}$/.test(delegate)) return json({ error: 'hash and delegate required' }, 400);
          const survey = await this.mcpVaultTool(g, 'list_vault_record', {}).then((r) => r.json()).catch(() => ({})) as { records?: Array<{ record_type: string }> };
          const keys = (survey.records ?? []).map((r) => r.record_type).filter((k) => k.startsWith(LINEAGE_RECORD_PREFIX));
          const records: DelegationLineageV1[] = [];
          if (keys.length) {
            const got = await this.mcpVaultTool(g, 'get_vault_records', { recordTypes: keys.slice(0, 200) }).then((r) => r.json()).catch(() => ({})) as { records?: Record<string, unknown> };
            for (const v of Object.values(got.records ?? {})) { const r = v as DelegationLineageV1; if (r?.type === 'ap.delegation-lineage.v1' && r.wire?.delegator?.toLowerCase() === principal) records.push(r); }
          }
          const answer = currentWireOf(records, want as Hex, delegate as Address);
          if (answer.status === 'unknown') {
            let revoked = true;
            try { revoked = (await this.pub().readContract({ address: this.env.DELEGATION_MANAGER as Address, abi: IS_REVOKED_ABI, functionName: 'isRevoked', args: [want as Hex] })) as boolean; } catch { revoked = true; }
            return json({ ok: true, status: revoked ? 'gone' : 'current', hash: want, wire: null });
          }
          return json({ ok: true, status: answer.status, hash: answer.hash, wire: answer.wire, ...(answer.status === 'superseded' ? { supersededFrom: answer.supersededFrom } : {}) });
        }
        // The WIRE of any grant this agent issued, by digest — asked for only by a revocation about to expand it.
        if (op === 'internal.grant.byDigest') {
          const want = String(body.digest ?? '').toLowerCase();
          if (!/^0x[0-9a-f]{64}$/.test(want)) return json({ error: 'digest required' }, 400);
          for (const prefix of [READ_GRANT_KEY(''), STANDING_GRANT_KEY(''), STUDY_GRANT_KEY('')]) {
            for (const [k, v] of await this.state.storage.list({ prefix })) {
              const rec = v as { wire?: IncomingDelegation; hash?: string };
              if (rec.hash?.toLowerCase() === want && rec.wire) return json({ ok: true, wire: rec.wire, hash: rec.hash, source: k });
            }
          }
          const survey = await this.mcpVaultTool(g, 'list_vault_record', {}).then((r) => r.json()).catch(() => ({})) as { records?: Array<{ record_type: string }> };
          const keys = (survey.records ?? []).map((r) => r.record_type).filter((k) => k.startsWith('org.invite:agent:') || k.startsWith('contact:'));
          if (keys.length) {
            const got = await this.mcpVaultTool(g, 'get_vault_records', { recordTypes: keys.slice(0, 200) }).then((r) => r.json()).catch(() => ({})) as { records?: Record<string, unknown> };
            for (const [k, v] of Object.entries(got.records ?? {})) {
              const rec = v as { delegation?: IncomingDelegation; grantDigest?: string };
              if (!rec.delegation) continue;
              const digest = (rec.grantDigest ?? hashDelegation({ ...rec.delegation, salt: BigInt(String(rec.delegation.salt)), caveats: rec.delegation.caveats.map((c) => ({ enforcer: c.enforcer, terms: c.terms, args: (c.args ?? '0x') as Hex })) } as Delegation, Number(this.env.CHAIN_ID ?? 84532), this.env.DELEGATION_MANAGER as Address)).toLowerCase();
              if (digest === want) return json({ ok: true, wire: rec.delegation, hash: digest, source: k });
            }
          }
          return json({ ok: true, wire: null });
        }
        if (op === 'internal.readgrant.list') {
          const rows = await this.state.storage.list({ prefix: READ_GRANT_KEY('') });
          const grants: Array<{ clientId: string; hash: string; storedAt: string; revoked: boolean }> = [];
          for (const [, v] of rows) {
            const rec = v as ReadGrantRecord;
            let revoked = false;
            try {
              revoked = (await this.pub().readContract({ address: this.env.DELEGATION_MANAGER as Address, abi: IS_REVOKED_ABI, functionName: 'isRevoked', args: [rec.hash as Hex] })) as boolean;
            } catch { revoked = true; }
            grants.push({ clientId: rec.clientId, hash: rec.hash, storedAt: rec.storedAt, revoked });
          }
          return json({ ok: true, grants });
        }

        // THE WIRE ITSELF — asked for only when something is about to REVOKE it, because
        // `revokeDelegationByOwner` takes the whole struct and a hash cannot be expanded back into one.
        // Handing out a signed delegation is not a disclosure risk here (it is the person's own grant,
        // returned to the person's own agent), but it is more than a list needs, which is why it is a
        // separate op rather than a field.
        // THE STUDY GRANT, for the person's own agent to present to the coach it is about to consult.
        // Read by in-Worker code only, for the principal whose grant it is; the coach's gate verifies it.
        if (op === 'internal.studygrant.wire') {
          const coach = String(body.coach ?? '').trim().toLowerCase();
          if (!coach) return json({ ok: false, error: 'coach required' }, 400);
          const rec = (await this.state.storage.get(STUDY_GRANT_KEY(coach))) as StudyGrantRecord | undefined;
          if (!rec) return json({ ok: false, error: `no study grant stored for "${coach}"` }, 404);
          return json({ ok: true, wire: rec.wire, hash: rec.hash, coach: rec.coach, delegate: rec.delegate });
        }
        if (op === 'internal.readgrant.wire') {
          const clientId = String(body.clientId ?? '').trim().toLowerCase();
          if (!clientId) return json({ ok: false, error: 'clientId required' }, 400);
          const rec = (await this.state.storage.get(READ_GRANT_KEY(clientId))) as ReadGrantRecord | undefined;
          if (!rec) return json({ ok: false, error: `no read grant stored for "${clientId}"` }, 404);
          return json({ ok: true, wire: rec.wire, hash: rec.hash, clientId: rec.clientId });
        }

        if (op === 'internal.coordination.vaultRead') {
          const recordType = String(body.recordType ?? '').trim();
          if (!recordType) return json({ error: 'recordType required' }, 400);
          if (!g) return json({ ok: false, needsEnable: true, error: 'interactions storage not enabled' });
          try {
            const data = await this.readDoc<unknown>(g, recordType, null);
            console.log(`[334§6 vaultRead] ${recordType} ok hasData=${data !== null && data !== undefined}`);
            return json({ ok: true, recordType, data });
          } catch (e) {
            const msg = e instanceof Error ? e.message : String(e);
            // WHAT "NEEDS ENABLING" LOOKS LIKE FROM HERE. A scope denial is one shape; the other is an
            // agent whose interactions plane was never provisioned at all — its vault has no grant, so
            // the MCP hop fails to AUTHENTICATE rather than to authorize ("auth failed"). Both are the
            // same permanent, actionable state: a steward turns storage on once. Reporting the second as
            // transient sent people to "try again later" for something that will never come right on its
            // own — which is what a team chartered through the Ask looked like, because that flow does
            // not provision the planes the Home's org-create does.
            const needsEnable = /record_scope_denied|scope|auth failed|no grant|grant_absent|not enabled/i.test(msg);
            console.log(`[334§6 vaultRead] ${recordType} FAILED needsEnable=${needsEnable} — ${msg.slice(0, 160)}`);
            return json({ ok: false, recordType, ...(needsEnable ? { needsEnable: true } : {}), error: msg });
          }
        }
        if (op === 'internal.coordination.vaultSurvey') {
          // THE INVENTORY, WITHOUT OPENING ANYTHING — spec 356 §2.5. `list` returns record keys and their
          // timestamps; no ciphertext is touched and no plaintext produced. This is what lets a question be
          // narrowed to CANDIDATES before a single record is decrypted.
          //
          // It is still a read of this principal's vault under this principal's grant: unencrypted never
          // means unauthorized. And the keys carry information — `org.invite:agent:0x…` names who was
          // invited — so this is a disclosure of low-sensitivity data, not of none.
          if (!g) return json({ ok: false, needsEnable: true, error: 'interactions storage not enabled' });
          try {
            const records = await this.vaultFor(g).list('');
            const rows = records.map((r) => ({ recordType: r.resource, updatedAt: r.updatedAt }));
            return json({ ok: true, records: rows, count: rows.length });
          } catch (e) {
            const msg = e instanceof Error ? e.message : String(e);
            return json({ ok: false, ...(/record_scope_denied|scope/i.test(msg) ? { needsEnable: true } : {}), error: msg });
          }
        }
        if (op === 'internal.coordination.vaultQuery') {
          // DECODE EXACTLY THE SELECTED RECORDS — spec 356 §2.5, phase two. ONE batched round trip
          // (`get_vault_records`, the seam the topic-body read already uses), because a per-record loop is
          // what exhausts a principal's verified-call budget.
          //
          // The caller names record types; the GRANT names whose vault. A record the grant's scope does not
          // cover simply does not come back — choosing a record authorizes nothing (ADR-0041).
          const requested = Array.isArray(body.recordTypes) ? (body.recordTypes as unknown[]).map((r) => String(r)).filter(Boolean) : [];
          if (!requested.length) return json({ error: 'recordTypes[] required' }, 400);
          if (!g) return json({ ok: false, needsEnable: true, error: 'interactions storage not enabled' });
          // Bounded: a question is answered from a handful of records, and an unbounded batch is how one
          // ask becomes a whole-vault read under another name.
          const recordTypes = [...new Set(requested)].slice(0, 25);
          try {
            const resp = await this.mcpVaultTool(g, 'get_vault_records', { recordTypes });
            const out = (await resp.json().catch(() => ({}))) as { ok?: boolean; records?: Record<string, unknown>; error?: string };
            if (!resp.ok || out.ok === false) return json({ ok: false, error: out.error ?? `vault batch read failed (${resp.status})` });
            const records = out.records ?? {};
            return json({ ok: true, records, read: Object.keys(records), requested: recordTypes });
          } catch (e) {
            return json({ ok: false, error: e instanceof Error ? e.message : String(e) });
          }
        }
        // ── spec 327 — the org-assistant pipeline's two internal ops (in-Worker marker only). ──
        if (op === 'internal.channels.read') {
          // Bounded topic context for the assistant turn: last N entries + clipped bodies. Same
          // storage path as the session-gated channels.read; reachable ONLY via the internal marker.
          const channelId = String(body.channelId ?? '');
          if (!channelId) return json({ error: 'channelId required' }, 400);
          const limit = Math.min(Math.max(Number(body.limit ?? ASSISTANT_READ_LIMIT) || ASSISTANT_READ_LIMIT, 1), ASSISTANT_READ_LIMIT);
          // The index, the topic and the playbook (spec 327 §4b — the context read carries it; absent ⇒
          // the built-in default, a config default, not a fallback) are three independent documents: one
          // wave, then the bodies of the entries kept. This read sits on the answering turn's critical
          // path, so its four serial hops were four seconds a person waited for every question.
          const [index, all, skill] = await Promise.all([
            this.readDoc<ChannelV1[]>(g, CONVERSATION_INDEX_RESOURCE, []),
            this.readDoc<ChannelMessageEntryV1[]>(g, TOPIC_RESOURCE(channelId), []),
            this.readDoc<AssistantSkillDocV1 | null>(g, ASSISTANT_SKILL_RESOURCE, null),
          ]);
          const entry = index.find((c) => c.descriptor.id === channelId);
          if (!entry) return json({ error: 'unknown channel' }, 404);
          const messages = all.slice(-limit);
          // ONE batched, hash-verified body read (same seam as the session-gated channels.read);
          // fail-closed omit per body — an unverifiable body renders empty, never fails the turn.
          const bodyById = await this.readTopicBodies(g, messages.map((m) => m.envelope)).catch(() => ({} as Record<string, string>));
          const rows = messages.map((m) => ({ id: m.envelope.id, from: m.envelope.from, authorName: m.authorName, ...(m.actor ? { actor: m.actor } : {}), createdAt: m.envelope.createdAt, bodyText: (bodyById[m.envelope.id] ?? '').slice(0, ASSISTANT_BODY_CLIP) }));
          return json({ ok: true, title: entry.title, messages: rows, ...(skill?.markdown ? { skillMarkdown: skill.markdown } : {}) });
        }
        if (op === 'internal.channels.create') {
          // AN ORGANIZATION OPENS A TOPIC ON ITS OWN BOARD, in-Worker (the card room's `club.topic`, 2026-09-18):
          // a club's game night is talked about where the club already talks, and the night's lines arrive as
          // posts from each character's own agent (`messaging.topic.post`, a member's act). The topic is OPEN —
          // every member takes part — and owned by the organization; the caller supplies only a title, so it
          // cannot author as anyone. IDEMPOTENT BY TITLE: a night asked for twice is the same topic, which is what
          // lets the card room hold no index of them.
          const title = String(body.title ?? '').trim().slice(0, 80);
          if (!title) return json({ error: 'title required' }, 400);
          return this.serialize(async () => {
            const index = await this.readDoc<ChannelV1[]>(g, CONVERSATION_INDEX_RESOURCE, []);
            const existing = index.find((ch) => ch.title.toLowerCase() === title.toLowerCase());
            if (existing) return json({ ok: true, channelId: existing.descriptor.id, title: existing.title, created: false });
            const ownerCaip = caip10(Number(this.env.CHAIN_ID ?? 84532), principal as Address) as ChannelV1['descriptor']['owner'];
            const r = createBoardChannel(index, { contextId: principal, owner: ownerCaip, title, createdBy: await this.boardNameFor(g, principal), participationPolicy: 'open', creatorSa: principal });
            if (!r.ok) return json({ error: r.error }, 400);
            await buildAuditSink(this.env).write({ id: crypto.randomUUID(), timestamp: new Date().toISOString(), action: 'interactions.channels.create', outcome: 'success', actor: { type: 'service', id: principal }, subject: { type: 'channel', id: r.channel.descriptor.id } });
            await this.writeDoc(g, CONVERSATION_INDEX_RESOURCE, index);
            return json({ ok: true, channelId: r.channel.descriptor.id, title, created: true });
          });
        }
        if (op === 'internal.channels.post') {
          // The assistant's reply write (spec 327 §5). `from`/`actor` are PINNED server-side to the
          // org principal — the caller supplies only { channelId, bodyText }; it cannot author as
          // anyone. Disable wins races: a reply landing after the steward disables is rejected.
          // Spec 400 W2 (B3) — OR a MEMBER AGENT's post, in-Worker after the harness verified its mandate
          // (`messaging.topic.post`): `member` names the author, which must hold this organization's invitation
          // (its record in the org's own vault); the author is then that member, never the org, and the assistant
          // need not be enabled — a member speaks in a topic as a member does.
          const channelId = String(body.channelId ?? '');
          const bodyText = String(body.bodyText ?? '').trim();
          if (!channelId || !bodyText) return json({ error: 'channelId + bodyText required' }, 400);
          const member = typeof body.member === 'string' && /^0x[0-9a-f]{40}$/i.test(body.member) ? body.member.toLowerCase() : null;
          const memberName = member ? String(body.memberName ?? '').trim().slice(0, 80) : '';
          if (member && member !== principal && !(await this.readDoc<unknown>(g, `org.invite:agent:${member}`, null))) return json({ error: 'that agent is not a member of this organization' }, 403);
          // spec 329 §6 — the routing turns' posts may carry the `routed-consultation` contextRef
          // (chip) + PROV attribution. PINNED: only that ref kind is accepted from the caller (the
          // in-Worker assistant pipeline), so this seam can never smuggle arbitrary refs.
          const extraRefs = (Array.isArray(body.contextRefs) ? (body.contextRefs as ContextRefV1[]) : [])
            .filter((r) => r?.kind === ROUTED_CONSULTATION_CONTEXT_KIND && typeof r.id === 'string' && r.id.trim())
            .slice(0, 2);
          const prov = body.prov && typeof body.prov === 'object' ? (body.prov as ConsultProvenanceV1) : undefined;
          const audit = buildAuditSink(this.env);
          return this.serialize(async () => { // ARCH-H1 — same single-writer append as every board post
            const [index, messages] = await Promise.all([ // the topic's id is known: both docs in one wave
              this.readDoc<ChannelV1[]>(g, CONVERSATION_INDEX_RESOURCE, []),
              this.readDoc<ChannelMessageEntryV1[]>(g, TOPIC_RESOURCE(channelId), []),
            ]);
            const entry = index.find((c) => c.descriptor.id === channelId);
            if (!entry) return json({ error: 'unknown channel' }, 404);
            const assistant = entry.assistant;
            if (!member && !assistant) return json({ error: 'assistant is not enabled on this topic' }, 409);
            const authorAddr = member && member !== principal ? member : principal;
            const authorCaip = caip10(Number(this.env.CHAIN_ID ?? 84532), authorAddr as Address) as AnyMessageEnvelope['from'];
            const authorName = member && member !== principal ? (memberName || member.slice(0, 10)) : (assistant?.displayName || memberName || principal.slice(0, 10));
            const composed: ChannelV1[] = [{ ...entry, messages }];
            const r = await appendBoardPost(composed, { channelId, from: authorCaip, authorName, bodyText, actor: authorCaip, ...(extraRefs.length ? { contextRefs: extraRefs } : {}), ...(prov ? { prov } : {}) });
            if (!r.ok) return json({ error: r.error }, 400);
            await audit.write({ id: crypto.randomUUID(), timestamp: r.envelope.createdAt, action: member && member !== principal ? 'interactions.channels.memberAgentPost' : 'interactions.channels.assistantPost', outcome: 'success', actor: { type: 'service', id: authorAddr }, subject: { type: 'channel-post', id: r.envelope.id } });
            const store = createVaultMessageBodyStore(this.vaultFor(g), principal);
            await store.putBody({ messageId: r.envelope.id, bytes: new TextEncoder().encode(bodyText), contentType: 'text/plain', classification: 'internal', resource: r.envelope.body.resource });
            await this.writeDoc(g, TOPIC_RESOURCE(channelId), composed[0]!.messages);
            await this.indexForSearch(r.envelope.id, { kind: 'topic', at: r.envelope.createdAt, snippet: '', ref: { org: principal, channelId, messageId: r.envelope.id, from: authorAddr, fromName: authorName, title: entry.title } }, bodyText);
            await this.recordOperation(body, 'send', r.envelope.id);
            return json({ ok: true, messageId: r.envelope.id });
          });
        }
        // ── spec 328 — the person-inbox assistant's two internal ops (in-Worker marker only). ──
        if (op === 'internal.inbox.read') {
          // Bounded conversation context for the assistant turn: last N envelopes + clipped
          // decoded bodies, plus the owner's playbook (one round trip — the 327 §4b pattern).
          const conversationId = String(body.conversationId ?? '');
          if (!conversationId) return json({ error: 'conversationId required' }, 400);
          const cfg = await this.readDoc<PersonAssistantV1 | null>(g, PERSON_ASSISTANT_RESOURCE, null);
          if (!cfg?.enabled) return json({ error: 'assistant is not enabled for this inbox' }, 409);
          const doc = await this.readDoc<{ envelopes?: MessageEnvelopeV1[] }>(g, INBOX_RESOURCE, {});
          const rows = (doc.envelopes ?? []).filter((e) => e.conversationId === conversationId).slice(-INBOX_ASSISTANT_READ_LIMIT);
          const messages = await Promise.all(rows.map(async (e) => {
            let text = '';
            if (e.body?.resource?.startsWith(DM_BODY_PREFIX)) {
              try {
                const r = await this.vaultFor(g).read<{ b64?: string }>({ owner: '', resource: e.body.resource });
                if (r?.data?.b64) text = new TextDecoder().decode(Uint8Array.from(atob(r.data.b64), (c) => c.charCodeAt(0))).slice(0, ASSISTANT_BODY_CLIP);
              } catch { /* fail-closed omit body */ }
            }
            const fromAddr = (String(e.from).match(/0x[0-9a-fA-F]{40}$/)?.[0] ?? '').toLowerCase();
            return { id: e.id, from: e.from, mine: fromAddr === principal, ...(e.actor ? { actor: e.actor } : {}), createdAt: e.createdAt, bodyText: text };
          }));
          // spec 354 K3 — the auto-reply turn speaks under the person's COMPILED ARCHETYPE (the digest-
          // verified `archetype.assignment` in their own vault), never a hand-typed markdown: one playbook,
          // one source, the same one every receipt cites. Absent or unverifiable ⇒ no instructions (the
          // turn keeps its built-in default — a config default, not a fallback mechanism).
          const playbook = await loadPlaybook((_subject, recordType) => this.readDoc<unknown>(g, recordType, null), principal, console.log);
          return json({ ok: true, displayName: cfg.displayName, messages, ...(playbook ? { playbook: playbook.instructions } : {}) });
        }
        if (op === 'internal.inbox.post') {
          // The assistant's reply write (spec 328 §5). `from`/`actor` are PINNED server-side to
          // the person principal (buildAssistantInboxReply); the caller supplies only
          // { conversationId, bodyText } — it cannot author as anyone, and the counterparty comes
          // from the OWNER'S OWN two-party descriptor, never the wire. Counterparty copy FIRST,
          // fail-closed; disable wins races (config re-read here).
          const conversationId = String(body.conversationId ?? '');
          const bodyText = String(body.bodyText ?? '').trim();
          if (!conversationId || !bodyText) return json({ error: 'conversationId + bodyText required' }, 400);
          const audit = buildAuditSink(this.env);
          return this.serialize(async () => { // ARCH-H1 — same single-writer merge as every inbox mutation
            const cfg = await this.readDoc<PersonAssistantV1 | null>(g, PERSON_ASSISTANT_RESOURCE, null);
            if (!cfg?.enabled) return json({ error: 'assistant is not enabled for this inbox' }, 409);
            const dg = st0.deliveryGrant;
            if (!dg) return json({ error: 'no delivery grant — enable inbox delivery for this agent first' }, 409);
            const doc = (await this.readDoc<Record<string, unknown>>(g, INBOX_RESOURCE, null as never)) ?? { version: 1, envelopes: [], events: [], draftCases: [], caseEvents: [], cards: {} };
            const personCaip = caip10(Number(this.env.CHAIN_ID ?? 84532), principal as Address) as AnyMessageEnvelope['from'];
            // spec 340 — a V2 reply MUST name what it answers (§R.4); `INFORM` alone cannot say
            // "this is a response". The antecedent is the newest message in this conversation that
            // did NOT come from the principal — which is precisely what the assistant is replying to.
            // Fail-closed: nothing inbound to answer ⇒ no reply, rather than an envelope that claims
            // to be an original.
            const convEnvelopes = ((doc.envelopes ?? []) as AnyMessageEnvelope[])
              .filter((e) => e.conversationId === conversationId && e.from !== personCaip);
            const antecedent = convEnvelopes[convEnvelopes.length - 1]?.id;
            if (!antecedent) return json({ error: 'no inbound message in this conversation to reply to' }, 409);
            const built = await buildAssistantInboxReply(doc.conversations as ConversationDescriptorV1[] | undefined, { principal: personCaip, conversationId, bodyText, inReplyTo: antecedent });
            if (!built.ok) return json({ error: built.error }, 409);
            const { envelope, counterpartyAddr, bodyBytes } = built;
            // Counterparty copy FIRST, fail-closed (the sendFromInbox "recipient side first" rule):
            // the counterparty's DO performs both admissions with ITS OWN held wires — exactly the
            // pair of calls the a2a messaging.deliver skill makes. Their internal.deliver runs
            // THEIR assistant scan, which skips this envelope (actor set — loop closed).
            let bin = '';
            for (const b of bodyBytes) bin += String.fromCharCode(b);
            const stored = { b64: btoa(bin), contentType: 'text/plain', bodyHash: envelope.bodyHash };
            const stub = this.env.INTERACTIONS.get(this.env.INTERACTIONS.idFromName(counterpartyAddr));
            const callOther = async (cop: string, payload: unknown): Promise<void> => {
              const resp = await stub.fetch(new Request(`https://do/interactions/${counterpartyAddr}/${cop}`, {
                method: 'POST', headers: internalHeaders(this.env), body: JSON.stringify(payload),
              }));
              const out = (await resp.json().catch(() => ({}))) as { ok?: boolean; error?: string };
              if (!resp.ok || out.ok === false) throw new Error(out.error ?? `${cop} failed (${resp.status})`);
            };
            await callOther('internal.dm.body.put', { resource: envelope.body.resource, data: stored });
            await callOther('internal.deliver', { envelope });
            // Own copy: body under the person's OWN delivery wire; envelope + 'sent' event under
            // the interactions grant (the sender's-copy half of sendFromInbox).
            await this.vaultFor(dg).write({ owner: '', resource: envelope.body.resource, data: stored, classification: 'internal' } as never);
            const envs = (doc.envelopes as MessageEnvelopeV1[] | undefined) ?? [];
            doc.envelopes = [...envs, envelope];
            const sent: MessageEventV1 = { version: 'ap.message.event.v1', messageId: envelope.id, actor: envelope.from, eventType: 'sent', at: envelope.createdAt };
            doc.events = [...((doc.events as unknown[] | undefined) ?? []), sent];
            await audit.write({ id: crypto.randomUUID(), timestamp: envelope.createdAt, action: 'interactions.inboxAssistant.post', outcome: 'success', actor: { type: 'service', id: principal }, subject: { type: 'message', id: envelope.id } });
            await this.writeDoc(g, INBOX_RESOURCE, doc);
            // Mark the reply seen — a later whole-doc diff never re-presents it (its actor marker
            // would skip anyway; this keeps the ledger honest).
            const seen = (await this.state.storage.get(INBOX_ASSISTANT_SEEN_KEY)) as string[] | undefined;
            if (seen) await this.state.storage.put(INBOX_ASSISTANT_SEEN_KEY, [...seen, envelope.id].slice(-INBOX_ASSISTANT_SEEN_CAP));
            return json({ ok: true, messageId: envelope.id });
          });
        }
        // ── spec 329 §3.2 — the consult turn's harness pre-read (in-Worker marker only): the
        // member's SKILL.md playbook (the spec-328 §4b record — ONE playbook governs auto-replies
        // AND consult answers) + their display name. Deliberately NOT gated on the auto-reply
        // assistant being enabled: consultability is its own opt-in (the delegation); the playbook
        // is guidance either way. Read-only; returns markdown + name, never bodies or mail.
        if (op === 'internal.resolution.grant') {
          // spec 338 §7 — the OWNER answered: this principal is handed a way to RESOLVE one unlisted
          // agent. Same shape and same justification as mail (`internal.deliver`): the recipient's own
          // DO writes into the recipient's own vault under the recipient's own grant. What differs is who
          // may cause it — the route that reaches this has already verified the issuer OWNS the target
          // and signed the grant, because a resolution grant nobody issued is just an address.
          //
          // IT IS NOT AUTHORITY. Holding this lets the recipient find where to send money. Moving any
          // still needs their own mandate, judged by the verifier (ADR-0056).
          // A REFERENCE, not an address: the holder is told WHOSE agent they may reach and which grant
          // says so. Where it is comes from the resolver, per use (spec 338 §4).
          const held = body.grant as { grantId?: string; owner?: string; targetType?: string } | undefined;
          if (!held?.grantId || !/^0x[0-9a-f]{40}$/.test(String(held.owner ?? '').toLowerCase())) {
            return json({ error: 'grant { grantId, owner } required' }, 400);
          }
          return this.serialize(async () => {
            const doc = await this.readDoc<{ grants?: unknown[] }>(g, RESOLUTION_GRANTS_RESOURCE, { grants: [] });
            const rows = Array.isArray(doc?.grants) ? doc.grants : [];
            // Re-issuing for the same (owner, kind) REPLACES: an owner who narrows, re-points or re-dates
            // a grant means the new one, and keeping both would let the holder present whichever suits.
            const key = `${String(held.owner).toLowerCase()}:${String(held.targetType ?? '').toLowerCase()}`;
            const next = [...rows.filter((r) => {
              const row = r as { owner?: string; targetType?: string; grantId?: string };
              return `${String(row.owner ?? '').toLowerCase()}:${String(row.targetType ?? '').toLowerCase()}` !== key
                && row.grantId !== held.grantId;
            }), held];
            await this.writeDoc(g, RESOLUTION_GRANTS_RESOURCE, { grants: next });
            return json({ ok: true });
          });
        }
        if (op === 'internal.resolution.approve') {
          // The owner's own record of what they decided. Kept because a grant that cannot be found later
          // cannot be revoked later, and revocation is the half of issuing that makes it safe to issue.
          const { requester, wants, grantId } = body as { requester?: string; wants?: string; grantId?: string };
          return this.serialize(async () => {
            const doc = await this.readDoc<{ requests?: unknown[] }>(g, RESOLUTION_REQUESTS_RESOURCE, { requests: [] });
            const rows = Array.isArray(doc?.requests) ? doc.requests : [];
            const key = `${String(requester ?? '').toLowerCase()}:${String(wants ?? '').toLowerCase()}`;
            const next = rows.map((r) => {
              const row = r as { kind?: string; requester?: string; wants?: string };
              if (row.kind === 'resolution.invitation.sent') return r; // the other end's row, not this decision
              return `${String(row.requester ?? '').toLowerCase()}:${String(row.wants ?? '').toLowerCase()}` === key
                // THE GRANT ITSELF STAYS HERE, with the issuer. The holder gets a reference and asks a
                // resolver for the address, which is what lets a withdrawal actually WITHHOLD it rather
                // than merely withhold the resolver's cooperation (spec 338 §4).
                ? { ...row, status: 'approved', grantId, grant: (body as { grant?: unknown }).grant ?? null, decidedAt: new Date().toISOString() } : r;
            });
            await this.writeDoc(g, RESOLUTION_REQUESTS_RESOURCE, { requests: next });
            return json({ ok: true });
          });
        }
        if (op === 'internal.resolution.revoke') {
          // THE OTHER HALF OF ISSUING. A grant you cannot take back is one you should think much harder
          // about giving, so revocation is what makes disclosure safe to do at all. The issuer's own row
          // is the status of record (`statusRef` points here); a checker reads it before honouring a
          // grant, and a revoked one stops working without waiting for its expiry.
          const grantId = String((body as { grantId?: string }).grantId ?? '');
          if (!grantId) return json({ error: 'grantId required' }, 400);
          return this.serialize(async () => {
            const doc = await this.readDoc<{ requests?: unknown[] }>(g, RESOLUTION_REQUESTS_RESOURCE, { requests: [] });
            const rows = Array.isArray(doc?.requests) ? doc.requests : [];
            let found = false;
            const next = rows.map((r) => {
              const row = r as { grantId?: string };
              if (row.grantId !== grantId) return r;
              found = true;
              return { ...row, status: 'revoked', revokedAt: new Date().toISOString() };
            });
            if (!found) return json({ ok: false, error: 'no grant of yours by that id' }, 404);
            await this.writeDoc(g, RESOLUTION_REQUESTS_RESOURCE, { requests: next });
            return json({ ok: true, grantId });
          });
        }
        if (op === 'internal.resolution.project') {
          // THE RESOLVER'S READ. Given a grantId this principal ISSUED, hand back the grant so the
          // resolver can check it and project the target. In-Worker only; the holder never reaches it,
          // which is the entire point of them holding a reference instead of an address.
          const grantId = String((body as { grantId?: string }).grantId ?? '');
          if (!grantId) return json({ error: 'grantId required' }, 400);
          const doc = await this.readDoc<{ requests?: unknown[] }>(g, RESOLUTION_REQUESTS_RESOURCE, { requests: [] });
          const row = (Array.isArray(doc?.requests) ? doc.requests : [])
            .find((r) => (r as { grantId?: string }).grantId === grantId) as { grant?: unknown; status?: string } | undefined;
          if (!row?.grant) return json({ ok: false, error: 'no such grant' }, 404);
          // A withdrawn grant projects NOTHING, reported as a refusal rather than an empty answer so a
          // caller cannot read "revoked" as "try again later".
          if (row.status === 'revoked') return json({ ok: false, error: 'revoked' }, 403);
          return json({ ok: true, grant: row.grant });
        }
        if (op === 'internal.resolution.status') {
          // Which of this principal's issued grants are no longer good. Read by the agent in-Worker when
          // someone tries to USE one — never handed to the holder, who would then be the one reporting
          // whether their own grant had been revoked.
          const doc = await this.readDoc<{ requests?: unknown[] }>(g, RESOLUTION_REQUESTS_RESOURCE, { requests: [] });
          const rows = Array.isArray(doc?.requests) ? doc.requests : [];
          const revoked = rows
            .filter((r) => (r as { status?: string }).status === 'revoked')
            .map((r) => (r as { grantId?: string }).grantId)
            .filter((x): x is string => !!x);
          return json({ ok: true, revoked });
        }
        if (op === 'internal.resolution.request') {
          // spec 338 §7 — someone ASKS this principal for a way to reach an unlisted agent of theirs.
          // It lands in their OWN vault under their OWN grant, exactly like an application: the request
          // is a question they will answer in their Home, and it confers nothing on arrival.
          // TWO KINDS IN ONE FAMILY, because they are two ends of one thing: a request RECEIVED (someone
          // asking this principal) and a request SENT (this principal waiting on someone). They dedupe on
          // different parties — the counterparty is the requester in one and the owner in the other — and
          // keying both on `requester` would collide every sent row against every other.
          const req = body.request as { kind?: string; requester?: string; owner?: string; wants?: string; purpose?: string; requestedAt?: string } | undefined;
          const sent = req?.kind === 'resolution.invitation.sent';
          const counterparty = String((sent ? req?.owner : req?.requester) ?? '').toLowerCase();
          if (!/^0x[0-9a-f]{40}$/.test(counterparty)) return json({ error: 'request { requester | owner } required' }, 400);
          return this.serialize(async () => {
            const doc = await this.readDoc<{ requests?: unknown[] }>(g, RESOLUTION_REQUESTS_RESOURCE, { requests: [] });
            const rows = Array.isArray(doc?.requests) ? doc.requests : [];
            // ONE pending request per (counterparty, wants, direction): asking twice is the same ask, and
            // letting it accumulate turns "anyone may ask" into a way to fill someone's Home with cards.
            const keyOf = (r: { kind?: string; requester?: string; owner?: string; wants?: string }): string => {
              const isSent = r.kind === 'resolution.invitation.sent';
              return `${isSent ? 'sent' : 'recv'}:${String((isSent ? r.owner : r.requester) ?? '').toLowerCase()}:${String(r.wants ?? '').toLowerCase()}`;
            };
            const key = keyOf(req ?? {});
            const next = [...rows.filter((r) => keyOf(r as never) !== key), { ...req, status: 'pending' }];
            await this.writeDoc(g, RESOLUTION_REQUESTS_RESOURCE, { requests: next });
            return json({ ok: true });
          });
        }
        if (op === 'internal.resolution.settle') {
          // THE FAR END OF A SENT REQUEST — spec 338 §7. They asked someone for a way to reach an agent,
          // it came back, and the payment it enabled has now settled. Closing the note is bookkeeping:
          // the GRANT it refers to is untouched and stays exactly as valid as its issuer left it, so this
          // withdraws nothing and permits nothing.
          //
          // SENT rows only. A received request is somebody else's decision and closes by being answered —
          // closing one from here would let a requester mark their own ask as dealt with.
          const owner = String(body.owner ?? '').toLowerCase();
          const wants = String(body.wants ?? '').toLowerCase();
          if (!/^0x[0-9a-f]{40}$/.test(owner)) return json({ error: 'owner required' }, 400);
          return this.serialize(async () => {
            const doc = await this.readDoc<{ requests?: unknown[] }>(g, RESOLUTION_REQUESTS_RESOURCE, { requests: [] });
            const rows = Array.isArray(doc?.requests) ? doc.requests : [];
            let closed = 0;
            const next = rows.map((r) => {
              const row = r as { kind?: string; owner?: string; wants?: string; status?: string };
              if (row.kind !== 'resolution.invitation.sent') return r;
              if (String(row.owner ?? '').toLowerCase() !== owner) return r;
              if (wants && String(row.wants ?? '').toLowerCase() !== wants) return r;
              if ((row.status ?? 'pending') !== 'pending') return r;
              closed += 1;
              return { ...row, status: 'settled', settledAt: new Date().toISOString(), ...(body.txHash ? { txHash: String(body.txHash) } : {}) };
            });
            // Nothing was waiting: not an error. A person may pay somebody they were never blocked on.
            if (closed) await this.writeDoc(g, RESOLUTION_REQUESTS_RESOURCE, { requests: next });
            return json({ ok: true, closed });
          });
        }
        if (op === 'internal.applications.append') {
          // spec 341 §5.5a — the ORG admitting an application into its OWN vault, under its OWN grant.
          // Reached only from this Worker (the `org.apply` skill), after the org's A2A gate verified
          // the applicant's transport grant. Nothing the applicant presented reaches this write.
          const app = body.application as { applicationId?: string; applicant?: string; message?: string; submittedAt?: string; subject?: string; record?: unknown } | undefined;
          const applicant = String(app?.applicant ?? '').toLowerCase();
          if (!app?.applicationId || !/^0x[0-9a-f]{40}$/.test(applicant)) {
            return json({ error: 'application { applicationId, applicant } required' }, 400);
          }
          return this.serialize(async () => {
            const doc = await this.readDoc<{ applications?: unknown[] }>(g, APPLICATIONS_RESOURCE, { applications: [] });
            const rows = Array.isArray(doc?.applications) ? doc.applications : [];
            // ONE entry per applicant: re-applying updates in place rather than accumulating, which is
            // what turns "anyone may apply" from a queue-flooding hole into an ordinary inbox.
            // One entry per APPLYING PARTY: the subject when a steward applied for an org, else the
            // applicant. Keying on the wrong one would let a steward's second attempt queue a
            // duplicate for the same organization.
            const key = String((app as { subject?: string }).subject ?? applicant).toLowerCase();
            const next = [...rows.filter((r) => {
              const row = r as { applicant?: string; subject?: string };
              return String(row.subject ?? row.applicant ?? '').toLowerCase() !== key;
            }), app];
            // DIAGNOSTIC (apply-chain): the applications doc lands populated and is later observed EMPTY,
            // with no approve/reject having run. An append can never PRODUCE an empty array — it always
            // writes at least the incoming row — so this logs what it read and what it wrote, to establish
            // whether the row is lost here (a stale read) or by some other writer.
            console.log(`[apply-append] org=${principal} read=${rows.length} write=${next.length} key=${key} appId=${app.applicationId}`);
            await this.writeDoc(g, APPLICATIONS_RESOURCE, { applications: next });
            return json({ ok: true });
          });
        }
        if (op === 'internal.consult.context') {
          // Same source as `internal.inbox.read`: the person's compiled archetype (spec 354 K3).
          const playbook = await loadPlaybook((_subject, recordType) => this.readDoc<unknown>(g, recordType, null), principal, console.log);
          const cfg = await this.readDoc<PersonAssistantV1 | null>(g, PERSON_ASSISTANT_RESOURCE, null);
          return json({
            ok: true,
            ...(playbook ? { playbook: playbook.instructions } : {}),
            ...(cfg?.displayName ? { displayName: cfg.displayName } : {}),
          });
        }
        // ── spec 329 W2/W3 — the org's routing internal ops (in-Worker marker only). ──
        if (op === 'internal.consult.eligible') {
          // The `find_members` ELIGIBILITY read (spec 329 §4): roster ∩ topic participants ∩
          // consultable-hinted ∩ grant-present, computed HERE (the org's single-reader execution
          // point) with the fabric pure intersection — the planner never widens this set.
          const channelId = String(body.channelId ?? '');
          if (!channelId) return json({ error: 'channelId required' }, 400);
          const index = await this.readDoc<ChannelV1[]>(g, CONVERSATION_INDEX_RESOURCE, []);
          const entry = index.find((c) => c.descriptor.id === channelId);
          if (!entry) return json({ error: 'unknown channel' }, 404);
          const routing = entry.routing;
          const wireRec = (await this.state.storage.get(ROUTING_ORG_WIRE_KEY)) as RoutingOrgWireRecord | undefined;
          if (!routing || !entry.assistant || !wireRec) {
            return json({ ok: true, enabled: false, maxFanout: 0, members: [] });
          }
          const now = new Date().toISOString();
          const rows = await this.readDoc<IndexedListing[]>(g, DIRECTORY_RESOURCE, []);
          const roster: ConsultRosterRowV1[] = rows.map((l) => ({
            subject: l.listing.subject,
            displayName: l.listing.displayName || l.label,
            consultable: l.listing.consultable === true,
            // spec 329 §12 — the member's self-asserted primary role in THIS org, straight from
            // their signed listing (never derived, never steward-set).
            ...(l.listing.orgRole?.trim() ? { orgRole: l.listing.orgRole.trim() } : {}),
            current: isListingCurrent(l.listing, now),
          }));
          const grantKeys = await this.state.storage.list({ prefix: consultGrantRecordKey('') });
          const grantMembers = [...grantKeys.keys()].map((k) => k.slice(consultGrantRecordKey('').length));
          const members = eligibleConsultMembers({ roster, channel: entry, grantMembers, orgSA: principal });
          return json({ ok: true, enabled: true, maxFanout: routing.maxFanout, members });
        }
        if (op === 'internal.session.leaf') {
          // Spec 384 W2 — THE AGENT SIGNS AS ITSELF. The DEL-001 session leaf (this principal → the
          // interactions-session key, principal-signed at the enable ceremony) is what lets this runtime speak
          // as the principal: a raw signature by the session key, wrapped with the leaf, verifies ERC-1271
          // against the principal. Handed ONLY in-Worker, to sign a firm offer as the provider. Nothing here
          // is authority — an offer grants nothing (336 §3.7).
          const st = ((await this.state.storage.get('state')) ?? {}) as StoredState;
          // An EXPIRED leaf is handed to nobody: a signature under it verifies nowhere, and saying so here — with the
          // window — is what lets the signer refuse in words instead of minting an "invalid" release (spec 412 W5).
          const live = this.sessionLeafLive(st);
          return json({ ok: true, leaf: live === false ? null : (this.activeLeaf(st) ?? st.sessionLeaf ?? null), leafLive: live, ...(st.sessionLeaves?.length ? { ladder: st.sessionLeaves.length } : {}), ...(live === false ? { reason: 'the session leaf has expired — the person refreshes it by opening their Home' } : {}) });
        }
        if (op === 'internal.consult.orgWire') {
          // The §3.1 wire, handed ONLY in-Worker to the org's own A2aTaskDO (the routing signer).
          const wireRec = (await this.state.storage.get(ROUTING_ORG_WIRE_KEY)) as RoutingOrgWireRecord | undefined;
          if (!wireRec) return json({ ok: true, wire: null });
          return json({ ok: true, wire: wireRec.wire, sessionKey: wireRec.sessionKey });
        }
        if (op === 'internal.consult.grant') {
          // ask_member's SEND-TIME grant re-read (spec 329 §8 stale-opt-in rule): the wire is
          // fetched fresh per send AND per turn-2 collection — a member whose grant row is gone is
          // dropped/marked revoked immediately, before the member's own gate would even be asked.
          const member = String(body.member ?? '').toLowerCase();
          if (!/^0x[0-9a-f]{40}$/.test(member)) return json({ error: 'member (address) required' }, 400);
          const rec = (await this.state.storage.get(consultGrantRecordKey(member))) as { wire?: IncomingDelegation } | undefined;
          return json({ ok: true, wire: rec?.wire ?? null });
        }
        if (op === 'internal.member.current') {
          // The messaging scope-class roster read (spec 341 §5.1c): which of these agents are CURRENT
          // members of THIS org — a current, ERC-1271-proven, non-tombstoned directory listing, the
          // same three tests `memberName` applies at the admission gate. Answered by the org's own DO
          // (the single reader of its directory) so the messaging gates never parse a roster they do
          // not own. Asked about a PERSON's DO by mistake, the directory is empty and the answer is
          // nobody — which is exactly "this target entry is not an org".
          const asked = Array.isArray(body.agents) ? (body.agents as unknown[]).map((a) => String(a).toLowerCase()) : [];
          if (asked.length === 0 || asked.length > 8) return json({ error: 'agents (1–8 addresses) required' }, 400);
          const rows = await this.readDoc<IndexedListing[]>(g, DIRECTORY_RESOURCE, []);
          const nowIso = new Date().toISOString();
          const stTomb = ((await this.state.storage.get('state')) ?? {}) as StoredState;
          const current: string[] = [];
          for (const addr of asked) {
            if (!/^0x[0-9a-f]{40}$/.test(addr)) continue;
            const row = rows.find(
              (l) => (l.listing.subject.match(/0x[0-9a-fA-F]{40}$/)?.[0] ?? '').toLowerCase() === addr && isListingCurrent(l.listing, nowIso),
            );
            if (!row) continue;
            if (stTomb.subjects?.[row.listing.subject.toLowerCase()]?.tombstoned) continue;
            const { proof, ...draft } = row.listing;
            const digest = await sha256Hex32(canonicalizeMessage(draft));
            if (!(await this.erc1271(addr as Address, digest as Hex, proof.signature as Hex))) continue;
            current.push(addr);
          }
          return json({ ok: true, current });
        }
        if (op === 'internal.member.recorded') {
          // A GOVERNED WORKSPACE'S BOARD ASKS ITS GOVERNOR (the owner's rule, 2026-10-02): a workspace holds no
          // members, so its gate cannot find one in its own vault; it asks the organization that governs it
          // whether this agent is a CURRENT member here. The same two tests this object's own gate applies —
          // the spec-382 membership record re-checked on chain, else a current ERC-1271-proven listing —
          // answered by the one object that reads this organization's records. A name, or null. Never a grant.
          const member = String(body.member ?? '').toLowerCase();
          if (!/^0x[0-9a-f]{40}$/.test(member)) return json({ error: 'member (address) required' }, 400);
          const name =
            (await this.recordedMemberName(g, principal, member as Address))
            ?? (await this.memberName(g, principal, `eip155:${Number(this.env.CHAIN_ID ?? 84532)}:${member}`));
          return json({ ok: true, name });
        }
        if (op === 'internal.member.role') {
          // THE MEMBER'S OWN AGENT ASKS WHAT THIS ORGANIZATION RECORDS OF THEM (spec 427 §5.3; capability
          // `person.roles.list`). In-Worker only, and the caller passes the run's VERIFIED asker — a person's agent
          // reads its own person's membership, the same answer `org.membership.mine` gives their session. Words,
          // never authority: the role is what they do here, and nothing gates on it.
          const member = String(body.member ?? '').toLowerCase();
          if (!/^0x[0-9a-f]{40}$/.test(member)) return json({ error: 'member (address) required' }, 400);
          return json(await this.membershipAnswer(g, principal, member));
        }
        if (op === 'internal.member.setRole') {
          // THE ORGANIZATION'S OWN AGENT SETS A MEMBER'S ROLE (capability `organization.member.role.set`) on a run that
          // presented the organization's mandate for exactly that act — the harness verified it; this object writes.
          // The offer is parsed here again: nothing reaches a membership record but ids and words (invariant 6).
          const member = String(body.member ?? '').toLowerCase();
          const by = String(body.by ?? '').toLowerCase();
          if (!/^0x[0-9a-f]{40}$/.test(member)) return json({ error: 'member (address) required' }, 400);
          if (!/^0x[0-9a-f]{40}$/.test(by)) return json({ error: 'by (the steward whose mandate this is) required' }, 400);
          const now = new Date().toISOString();
          let fields: AssignedRoleFields;
          if (body.orgRole === null || body.orgRole === undefined) {
            fields = { assignedRole: PLAIN_MEMBER, assignedBy: by, assignedAt: now, roleSetAt: now };
          } else {
            const parsed = parseRoleOffer(body.orgRole);
            if (!parsed.ok) return json({ ok: false, code: 'invalid_role_offer', error: parsed.error }, 400);
            fields = { ...roleFieldsFromOffer(parsed.offer, by, now), roleSetAt: now };
          }
          return this.setMemberRole(g, principal, member, fields, by, buildAuditSink(this.env));
        }
        if (op === 'internal.library.packages') {
          // Every package in this org's library, FRONTMATTER ONLY. The archetype catalog is derived
          // from it rather than hand-maintained, because a catalog that can disagree with the
          // library advertises roles whose definition the harness cannot load — and that failure
          // surfaces to a caller as a rejected task, not as "the advertisement was stale".
          const dg = st0.deliveryGrant;
          if (!dg) return json({ error: 'no delivery grant — enable storage for this org first' }, 409);
          const cat = await this.vaultFor(dg).read<unknown>({ owner: '', resource: 'content.catalog' });
          const list = Array.isArray(cat?.data) ? (cat.data as Array<Record<string, unknown>>) : [];
          const out: Array<{ name: string; frontmatter: string }> = [];
          for (const a of list) {
            if (a?.isFolder === true) continue;
            if (String(a?.name ?? '') !== 'SKILL.md') continue;
            const folder = String(a?.folder ?? '');
            if (!folder.startsWith('skills/')) continue;
            const pkg = folder.slice('skills/'.length);
            if (!pkg || pkg.includes('/')) continue;          // top-level packages only
            const rec = await this.vaultFor(dg).read<Record<string, unknown>>({ owner: '', resource: `content.artifact.${String(a.id)}` });
            const b64 = String((rec?.data as Record<string, unknown> | undefined)?.bytesB64 ?? '');
            if (!b64) continue;
            try {
              const bin = atob(b64);
              const text = new TextDecoder().decode(Uint8Array.from(bin, (ch) => ch.charCodeAt(0)));
              // Frontmatter only — the bodies are large and a catalog needs none of them.
              const m = /^---\n([\s\S]*?)\n---/.exec(text);
              out.push({ name: pkg, frontmatter: m ? m[1]! : '' });
            } catch { /* an unreadable package is omitted, not fatal */ }
          }
          return json({ ok: true, packages: out });
        }
        if (op === 'internal.archetype.hosts') {
          // THE GRANT STORE IS THE ROUTING TABLE. "Which org hosts the Ontologist?" has no general
          // answer, but "which org has granted ME its Ontologist?" does — and it is the only one
          // that matters, because a host we hold no grant from is not reachable anyway. Routing
          // therefore follows authority instead of a configured directory that could disagree with it.
          const prefix = archetypeGrantRecordKey('');
          const rows = await this.state.storage.list({ prefix });
          const hosts: Array<{ host: string; archetypes: string[]; grantedAt?: string }> = [];
          for (const [, v] of rows) {
            const r = v as { host?: string; archetypes?: string[]; grantedAt?: string };
            if (r?.host) hosts.push({ host: r.host, archetypes: r.archetypes ?? [], ...(r.grantedAt ? { grantedAt: r.grantedAt } : {}) });
          }
          return json({ ok: true, hosts });
        }
        if (op === 'internal.archetype.grant') {
          // Send-time read of the HOST's dispatch opt-in, same stale-opt-in rule as consult: fetched
          // fresh per send, so a host that revoked is refused here rather than at its own gate.
          const host = String(body.host ?? '').toLowerCase();
          if (!/^0x[0-9a-f]{40}$/.test(host)) return json({ error: 'host (address) required' }, 400);
          const rec = (await this.state.storage.get(archetypeGrantRecordKey(host))) as { wire?: IncomingDelegation } | undefined;
          return json({ ok: true, wire: rec?.wire ?? null });
        }
        // ── spec 334 §4 door 4 (W4) — the A2A intent door, in-Worker marker only. The A2aTaskDO
        // orchestrate skill calls here AFTER its delegation gate verified the task sender; that
        // VERIFIED sender is the requester. Pinned to exactly `endeavor.request` (never arbitrary
        // endeavor.* ops), and it runs the SAME engine as every door — handleEndeavorOp →
        // SubmitEndeavorRequest → the reducer (one engine, four doors). ──
        if (op === 'internal.endeavor.request') {
          const requester = String(body.requester ?? '').toLowerCase();
          if (!/^0x[0-9a-f]{40}$/.test(requester)) return json({ error: 'requester (the verified task sender) required' }, 400);
          const chainId = Number(this.env.CHAIN_ID ?? 84532);
          const doorAudit = buildAuditSink(this.env);
          const res = await handleEndeavorOp({
            principal,
            // Spec 375 — the events a commit appends fire the participants' triggers, off the mutex.
            onCommitted: (endeavorId, events, state) => { this.state.waitUntil(afterEndeavorCommit(this.env, principal as Address, endeavorId, events as never, state).catch(() => undefined)); },
            principalCaip: caip10(chainId, principal as Address),
            sessionSa: requester,
            sessionCaip: caip10(chainId, requester as Address),
            readDoc: <T,>(resource: string, empty: T): Promise<T> => this.readDoc<T>(g, resource, empty),
            writeDoc: (resource: string, data: unknown): Promise<void> => this.writeDoc(g, resource, data),
            serialize: <T,>(fn: () => Promise<T>): Promise<T> => this.serialize(fn),
            // This door carries NO member session and NO stewardship wire — both honestly absent
            // (endeavor.request needs neither; any gated op through this door fails closed).
            memberName: async () => null,
            isSteward: async () => false,
            verifySignature: (account, digest, signature) => this.erc1271(account as Address, digest as Hex, signature as Hex),
            writeAudit: (action, subject, timestamp) =>
              doorAudit.write({ id: crypto.randomUUID(), timestamp: timestamp ?? new Date().toISOString(), action, outcome: 'success', actor: { type: 'service', id: requester }, subject }),
            putTopicBody: async (envelope, bodyText) => {
              const store = createVaultMessageBodyStore(this.vaultFor(g), principal);
              await store.putBody({ messageId: envelope.id, bytes: new TextEncoder().encode(bodyText), contentType: 'text/plain', classification: 'internal', resource: envelope.body.resource });
            },
          }, 'endeavor.request', body);
          // Auto-work: an A2A intent that landed a request gets auto-triaged too (no-op unless on).
          if (res.ok) {
            const rid = ((await res.clone().json().catch(() => ({}))) as { requestId?: string }).requestId;
            if (rid) this.dispatchEndeavorAutoAdopt(principal, rid);
          }
          return res;
        }
        // ── spec 334 §6 — the org agent's plan-draft return path. Pinned to exactly
        // `endeavor.proposePlan` with the ORG ITSELF as actor (the reducer's managing-principal
        // gate admits it); the internal marker is the authorization — this is the org's own
        // substrate posting its own draft, never a caller-supplied actor. ──
        if (op === 'internal.endeavor.proposePlan') {
          const chainId = Number(this.env.CHAIN_ID ?? 84532);
          const doorAudit = buildAuditSink(this.env);
          return handleEndeavorOp({
            principal,
            // Spec 375 — the events a commit appends fire the participants' triggers, off the mutex.
            onCommitted: (endeavorId, events, state) => { this.state.waitUntil(afterEndeavorCommit(this.env, principal as Address, endeavorId, events as never, state).catch(() => undefined)); },
            principalCaip: caip10(chainId, principal as Address),
            sessionSa: principal,
            sessionCaip: caip10(chainId, principal as Address),
            readDoc: <T,>(resource: string, empty: T): Promise<T> => this.readDoc<T>(g, resource, empty),
            writeDoc: (resource: string, data: unknown): Promise<void> => this.writeDoc(g, resource, data),
            serialize: <T,>(fn: () => Promise<T>): Promise<T> => this.serialize(fn),
            // The org agent at its own internal door: identified as the organization itself (the
            // DO-level member gate admits it; the reducer's actor gate is the real authority).
            memberName: async () => 'Organization agent',
            isSteward: async () => false,
            verifySignature: (account, digest, signature) => this.erc1271(account as Address, digest as Hex, signature as Hex),
            writeAudit: (action, subject, timestamp) =>
              doorAudit.write({ id: crypto.randomUUID(), timestamp: timestamp ?? new Date().toISOString(), action, outcome: 'success', actor: { type: 'service', id: principal }, subject }),
            putTopicBody: async (envelope, bodyText) => {
              const store = createVaultMessageBodyStore(this.vaultFor(g), principal);
              await store.putBody({ messageId: envelope.id, bytes: new TextEncoder().encode(bodyText), contentType: 'text/plain', classification: 'internal', resource: envelope.body.resource });
            },
          }, 'endeavor.proposePlan', body);
        }
        // ── spec 334 §6 auto-work — the principal's OWN agent driving its endeavors. Each door pins
        // exactly ONE endeavor op with the principal as actor; the internal marker is authorization.
        // `internal.endeavor.state` is a raw, un-gated read (the autopilot's own substrate reading its
        // own log — no viewer visibility gates apply to the principal reading itself).
        if (op === 'internal.endeavor.state') {
          let endeavorId = String(body.endeavorId ?? '');
          // ACCEPT THE ID THE SUBMITTER WAS GIVEN. `endeavor.request` hands back an `ereq_` requestId;
          // the `end_` id only exists once the org ADOPTS it, and nothing told the submitter what it
          // became — so a dispatcher could name what it raised and never look it up. The mapping is
          // already on the request row (`status` + `endeavorId`); this reads it rather than adding a
          // second source. A request that is not adopted yet answers WITH ITS STATUS instead of a
          // 404, because "not adopted yet" and "no such thing" are different facts with different
          // next steps, and collapsing them is what makes a caller poll forever.
          if (endeavorId.startsWith('ereq_')) {
            console.log('[internal.endeavor.state] resolving request', endeavorId);
            let reqs: CoordinationRequestsDocV1;
            try {
              reqs = await this.readDoc<CoordinationRequestsDocV1>(g, COORDINATION_REQUESTS_RESOURCE, { version: 1, rows: [] });
            } catch (e) {
              // The read that fails here is the one that makes a dispatched intent unfollowable, and
              // it surfaced to the caller as a bare 409. Name it.
              console.error('[internal.endeavor.state] requests read FAILED', e instanceof Error ? e.message : String(e));
              throw e;
            }
            const row = reqs.rows.find((r) => r.request.requestId === endeavorId);
            if (!row) return json({ error: 'unknown request' }, 404);
            if (!row.endeavorId) {
              return json({
                ok: true,
                requestId: row.request.requestId,
                status: row.status,                       // pending | declined
                lifecycle: null,
                goal: row.request.goal,
                requester: row.request.requester?.toLowerCase() ?? null,
                adoptedPlanRef: null,
                latestPlan: null,
                plan: null,
                ...(row.reason ? { reason: row.reason } : {}),
              });
            }
            endeavorId = row.endeavorId;
          }
          if (!endeavorId.startsWith('end_')) return json({ error: 'endeavorId required' }, 400);
          let log: CoordinationEventV1[];
          try {
            log = await this.readDoc<CoordinationEventV1[]>(g, coordinationEventsResource(endeavorId), []);
          } catch (e) {
            console.error('[internal.endeavor.state] event-log read FAILED', { endeavorId, why: e instanceof Error ? e.message : String(e) });
            throw e;
          }
          console.log('[internal.endeavor.state] log read', { endeavorId, events: log.length });
          if (log.length === 0) return json({ error: 'unknown endeavor' }, 404);
          const state = reduceEventLog(log);
          const adoptedRef = state.endeavor?.adoptedPlanRef ?? null;
          const all = Object.values(state.plans);
          const latest = all.sort((a, b) => b.revision - a.revision)[0] ?? null;
          const plan = adoptedRef
            ? all.find((p) => p.planId === adoptedRef.planId && p.revision === adoptedRef.revision) ?? null
            : latest;
          // The closing note the coordinator recorded when the endeavor was satisfied — the answer to
          // "what came of it", which lives on the event rather than in the reduced state.
          //
          // FAIL SOFT. This is an ENRICHMENT of a read that has to keep working: if decoding the
          // outcome throws, the caller should still learn the lifecycle and the plan. Letting it
          // propagate turned a state read into a 409 and made every dispatched build unfollowable —
          // the observation broke, so the work looked broken.
          let outcome: string | null = null;
          try {
            const satisfiedEvent = [...log].reverse().find((e) => e.kind === 'EndeavorSatisfied') as
              | { outcomeValidationRef?: { iri?: string } }
              | undefined;
            outcome = decodeInlineRef(satisfiedEvent?.outcomeValidationRef?.iri);
          } catch (e) {
            console.warn('[endeavor.state] outcome decode failed', e instanceof Error ? e.message : String(e));
          }
          return json({
            ok: true,
            endeavorId,
            status: 'adopted',
            ...(outcome ? { outcome } : {}),
            lifecycle: state.endeavor?.lifecycle ?? null,
            // Prefer the FULL request goal — the endeavor title is truncated to 80 chars at adopt
            // time, and the work turns need the whole ask.
            goal: state.request?.record.goal ?? state.endeavor?.title ?? '',
            requester: state.request?.record.requester?.toLowerCase() ?? null,
            adoptedPlanRef: adoptedRef,
            latestPlan: latest ? { planId: latest.planId, revision: latest.revision, contentHash: latest.contentHash, proposedBy: latest.proposedBy.toLowerCase() } : null,
            // Spec 382 — the ACTIVE commitments, so the work turn knows which steps are somebody else's promise.
            commitments: Object.values(state.commitments).filter((c) => c.status === 'active').map((c) => ({ commitmentId: c.commitmentId, participant: c.participant.toLowerCase(), steps: c.steps, planRef: c.planRef, allocationRef: c.allocationRef })),
            plan: plan
              ? {
                  planId: plan.planId,
                  revision: plan.revision,
                  contentHash: plan.contentHash,
                  proposedBy: plan.proposedBy.toLowerCase(),
                  steps: plan.steps.map((s) => {
                    const done = state.satisfiedSteps[s.stepId];
                    // The deliverable, not just a tick: a requester following its own intent needs
                    // what the step PRODUCED, and it is already here. Same fail-soft rule as the
                    // outcome — a step whose evidence will not decode still reports as satisfied.
                    let evidence: string | null = null;
                    try {
                      evidence = done?.evidenceRefs?.map((r) => decodeInlineRef((r as { iri?: string }).iri)).find((t): t is string => !!t) ?? null;
                    } catch { /* enrichment only */ }
                    // WHAT THE STEP NEEDS, carried through. This projection is a SECOND one — the
                    // `planProjection` fix did not reach it — and it was the last place the
                    // capability was dropped: correct from the model, through the command, the
                    // event and stored state, then flattened away one hop before the reader. Two
                    // views of the same plan is why fixing one looked like fixing none.
                    return {
                      stepId: s.stepId, kind: s.kind, description: s.description, satisfied: !!done,
                      ...(s.capabilityRequirements?.length ? { capabilityRequirements: s.capabilityRequirements } : {}),
                      ...(evidence ? { evidence } : {}),
                    };
                  }),
                }
              : null,
          });
        }
        if (op === 'internal.endeavor.create') {
          return handleEndeavorOp(this.endeavorSelfDeps(g, principal, { steward: true }), 'endeavor.create', { ...body, decision: 'adopt' });
        }
        if (op === 'internal.endeavor.adoptPlan') {
          return handleEndeavorOp(this.endeavorSelfDeps(g, principal, { steward: true }), 'endeavor.adoptPlan', body);
        }
        if (op === 'internal.endeavor.satisfyStep') {
          // Spec 382 — a participant's finished run records ITS step as the participant (the reducer re-gates).
          return handleEndeavorOp(this.endeavorSelfDeps(g, principal, { ...(typeof body.actor === 'string' ? { actor: body.actor } : {}) }), 'endeavor.satisfyStep', body);
        }
        if (op === 'internal.endeavor.satisfy') {
          return handleEndeavorOp(this.endeavorSelfDeps(g, principal), 'endeavor.satisfy', body);
        }
        if (op === 'internal.endeavor.post') {
          return handleEndeavorOp(this.endeavorSelfDeps(g, principal), 'endeavor.post', body);
        }
        if (op === 'invite.get' || op === 'invite.put') {
          // spec 323 W3.2 — the org's invite records (`org.invite:*`) read/written via the DO-held
          // delivery wire (its r+w scope covers org.invite); replaces orgVault's KV-wire transport so
          // the Home stores no org wire either. Namespace-pinned belt to the wire's own record scope.
          const dg = st0.deliveryGrant;
          if (!dg) return json({ error: 'no delivery grant — enable storage for this org first' }, 409);
          const resource = String(body.resource ?? '');
          if (!resource.startsWith('org.invite:')) return json({ error: 'org.invite resources only' }, 400);
          if (op === 'invite.get') {
            const r = await this.vaultFor(dg).read<unknown>({ owner: '', resource });
            return json({ ok: true, record: r?.data ?? null });
          }
          if (body.data === undefined) return json({ error: 'data required' }, 400);
          // Spec 427 invariant 6 — a ROLE OFFER on an invitation carries ids and words only. Checked at the door
          // the record is written through, so no caller can store one this object would later refuse to read.
          const offered = (body.data && typeof body.data === 'object' ? (body.data as { orgRole?: unknown }).orgRole : undefined);
          if (offered !== undefined && offered !== null) {
            const parsed = parseRoleOffer(offered);
            if (!parsed.ok) return json({ ok: false, code: 'invalid_role_offer', error: parsed.error }, 400);
          }
          await this.vaultFor(dg).write({ owner: '', resource, data: body.data, classification: 'internal' } as never);
          // The room says so (Welcome topic): an invitation went out — to a named agent, or by email (the
          // address itself is never on the board; the record never held it either).
          if (op === 'invite.put' && st0.grant) {
            const data = (body.data && typeof body.data === 'object' ? body.data : {}) as { invitedBy?: string; displayName?: string; status?: string; kin?: string; orgRole?: { name?: string } | null };
            if (!data.status || data.status === 'pending') {
              const by = typeof data.invitedBy === 'string' && /^0x[0-9a-f]{40}$/i.test(data.invitedBy) ? await this.boardNameFor(st0.grant, data.invitedBy) : null;
              const who = resource.startsWith('org.invite:agent:') ? await this.boardNameFor(st0.grant, resource.slice('org.invite:agent:'.length)) : (data.displayName || 'someone, by email');
              // A household's line says the kinship (spec 368) — "invited Bob to join as spouse".
              // …and an organization's line says the role it offered (spec 427) — "invited Bob to join as Field worker".
              const asKin = typeof data.kin === 'string' && data.kin.trim() ? ` as ${data.kin.trim()}` : (data.orgRole && typeof data.orgRole.name === 'string' && data.orgRole.name.trim() ? ` as ${data.orgRole.name.trim().slice(0, 60)}` : '');
              await this.postWelcome(st0.grant, principal, `📨 ${by ? `${by} invited` : 'An invitation went to'} ${who}${by ? ' to join' : ''}${asKin}.`);
            }
          }
          return json({ ok: true });
        }
        if (op === 'content.getMany') {
          // MANY OF THE ORG'S CONTENT RECORDS IN ONE VAULT ROUND TRIP. A library listing hydrates a folder's
          // artifacts, and it did so with one `content.get` per artifact — a steward opening a team that holds a few
          // hundred records paid a few hundred hops through this object. Same wire (the delivery grant), same
          // `content.` namespace pin, the vault's own batch read.
          //
          // FOR A CALLER THE GATE ADMITS WHOLE — a steward, the owner, the bridge. A SCOPED grant is judged one
          // resource at a time (`scopedContentOp`), and a batch has many; rather than restate that judgement here
          // and risk the two disagreeing, a scoped caller is refused and keeps the per-record read.
          if (scopedGrants) return json({ error: 'a scoped grant reads one record at a time — use content.get' }, 403);
          const dg = st0.deliveryGrant;
          if (!dg) return json({ error: 'no delivery grant — enable storage for this org first' }, 409);
          const resources = (Array.isArray(body.resources) ? body.resources : []).filter((r): r is string => typeof r === 'string').slice(0, 200);
          if (resources.some((r) => !r.startsWith('content.'))) return json({ error: 'content.* resources only' }, 400);
          if (!resources.length) return json({ ok: true, records: {} });
          const resp = await this.mcpVaultTool(dg, 'get_vault_records', { recordTypes: resources });
          const got = (await resp.json().catch(() => ({}))) as { ok?: boolean; records?: Record<string, unknown>; error?: string };
          // A batch that failed is an error, never an empty answer: "no bytes" would read as "nothing stored".
          if (!resp.ok || got.ok === false || !got.records) return json({ error: `content.getMany: ${got.error ?? `the vault answered ${resp.status}`}` }, 502);
          return json({ ok: true, records: got.records });
        }
        if (op === 'content.get' || op === 'content.put') {
          // ADR-0055 — the ORG's own Content Artifacts (`content.*`), read/written via the DO-held delivery
          // wire (its scope now covers vault:content.*). Steward-gated upstream (demo-sso-next scopeFor →
          // stewardWireFor), bridge-gated here; namespace-pinned to `content.` as a belt to the wire scope.
          // Mirrors invite.* — the org analogue of the person's self-gated record.*/content.catalog path.
          const dg = st0.deliveryGrant;
          if (!dg) return json({ error: 'no delivery grant — enable storage for this org first' }, 409);
          const resource = String(body.resource ?? '');
          if (!resource.startsWith('content.')) return json({ error: 'content.* resources only' }, 400);
          if (op === 'content.get') {
            const r = await this.vaultFor(dg).read<unknown>({ owner: '', resource });
            return json({ ok: true, record: r?.data ?? null });
          }
          if (body.data === undefined) return json({ error: 'data required' }, 400);
          /*
            THE INDEX IS MAINTAINED HERE, NOT REPLACED BY THE CALLER.

            `content.catalog` lists every artifact in the organization, and demo-sso-next rewrites the
            WHOLE list on every save (`library.ts` — `scope.write(list)` runs before the artifact is
            written). For a steward that is harmless: they may write all of it anyway. For a SCOPED
            writer it is the entire problem — replacing the index wholesale would let a grant naming
            one community drop another community's records out of it, which is a deletion wearing a
            save, and it would also let a stale list roll back somebody else's concurrent write.

            So a scoped caller's catalog write is MERGED. Entries their grant actually covers are
            taken from the submission; every other entry is preserved from what is stored. They cannot
            remove what they could not have written. A steward still replaces the list outright —
            merging for them would only stop their deletes working.
          */
          if (resource === 'content.catalog' && scopedGrants && Array.isArray(body.data)) {
            const stored = ((await this.vaultFor(dg).read<unknown>({ owner: '', resource }))?.data ?? []) as Array<{ id?: string }>;
            const mine = (e: { id?: string }): boolean =>
              vaultRecordScopeAllows(scopedGrants!, {
                server: vaultServerId(this.env),
                resource: `vault:content.artifact.${String(e.id ?? '')}`,
                op: 'write',
              });
            const merged = [...stored.filter((e) => !mine(e)), ...(body.data as Array<{ id?: string }>).filter(mine)];
            await this.vaultFor(dg).write({ owner: '', resource, data: merged, classification: 'internal' } as never);
            return json({ ok: true, merged: merged.length });
          }
          await this.vaultFor(dg).write({ owner: '', resource, data: body.data, classification: 'internal' } as never);
          return json({ ok: true });
        }
        if (op === 'internal.library.skillMd') {
          // ONE PACKAGE FILE, READ IN PLACE. An archetype agent's SKILL.md is an artifact in THIS
          // org's own Content Artifact library (`skills/<name>/SKILL.md`), and the A2A skill that
          // acts as that archetype needs it as a harness read.
          //
          // It is read where it lives — catalog then artifact, exactly the two records
          // `connect/library` itself writes (ADR-0055) — rather than being mirrored into a
          // bespoke record. A copy would be a second home for the same bytes with no answer to
          // which is authoritative, and it would go stale the moment a steward edits the package.
          //
          // Both hops happen INSIDE the DO because both need the delivery wire the DO holds; doing
          // it from the caller would mean two bridge round trips and the artifact id crossing a
          // boundary for no purpose. Marker-gated like every other `internal.` op.
          const dg = st0.deliveryGrant;
          if (!dg) return json({ error: 'no delivery grant — enable storage for this org first' }, 409);
          const name = String(body.name ?? '').trim();
          // The folder is built here from a validated single label, never taken from the caller —
          // a caller-supplied folder would read any artifact in the library, not just a skill.
          if (!/^[a-z0-9][a-z0-9-]{0,60}$/.test(name)) return json({ error: 'invalid skill package name' }, 400);
          const folder = `skills/${name}`;
          const file = String(body.file ?? 'SKILL.md').trim() || 'SKILL.md';
          if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,120}$/.test(file)) return json({ error: 'invalid file name' }, 400);

          const cat = await this.vaultFor(dg).read<unknown>({ owner: '', resource: 'content.catalog' });
          const list = Array.isArray(cat?.data) ? (cat.data as Array<Record<string, unknown>>) : [];
          const hit = list.find((a) => a?.isFolder !== true && String(a?.folder ?? '') === folder && String(a?.name ?? '') === file);
          if (!hit?.id) return json({ ok: true, found: false, text: null });

          const rec = await this.vaultFor(dg).read<Record<string, unknown>>({ owner: '', resource: `content.artifact.${String(hit.id)}` });
          const b64 = String((rec?.data as Record<string, unknown> | undefined)?.bytesB64 ?? '');
          if (!b64) return json({ ok: true, found: false, text: null });
          // UTF-8 safe: atob is latin-1, and every SKILL.md in this stack has em dashes in it.
          let text = '';
          try {
            const bin = atob(b64);
            text = new TextDecoder().decode(Uint8Array.from(bin, (ch) => ch.charCodeAt(0)));
          } catch { return json({ ok: true, found: false, text: null }); }
          return json({ ok: true, found: true, text, artifactId: String(hit.id), version: (rec?.data as Record<string, unknown> | undefined)?.version ?? null });
        }
        if (op === 'dm.body.put' || op === 'internal.dm.body.put') {
          // spec 323 W3 — dm body WRITE via the DO-held DELIVERY wire (the only wire scoped to write
          // dm bodies). `dm.body.put` = the Home's split-plane writer over the bridge; the in-Worker
          // `internal.dm.body.put` is the a2a deliver skill. dm-namespace pinned (belt to the wire's
          // own write-only record scope).
          const dg = st0.deliveryGrant;
          if (!dg) return json({ error: 'no delivery grant — enable inbox delivery for this agent first' }, 409);
          const resource = String(body.resource ?? '');
          if (!resource.startsWith(DM_BODY_PREFIX)) return json({ error: 'dm body resources only' }, 400);
          if (body.data === undefined) return json({ error: 'data required' }, 400);
          // DM-BODY-OVERWRITE-1 — the resource id is sender-controlled beyond the dm: prefix and the write is
          // last-writer-wins. A sender who knows an existing message id could overwrite that slot with a body
          // whose hash no longer matches the persisted envelope's bodyHash → the recipient's loadBody sees a
          // hash mismatch and silently drops the message (per-message censorship). DM bodies are write-once:
          // reject an overwrite whose bodyHash differs (an idempotent same-hash re-delivery still succeeds).
          const incomingHash = (body.data as { bodyHash?: string } | null)?.bodyHash;
          // The write-once guard READS the existing body — but the DELIVERY grant (dg) is WRITE-ONLY on dm
          // bodies (record scope `message.body:dm:*` : write), so reading with it is record_scope_denied and
          // NO dm ever writes. Read via the INTERACTIONS grant instead (st0.grant carries `message.body:dm:*`
          // : read); the delivery grant still performs the WRITE. Participants enable both planes together,
          // so require the interactions grant here and fail CLOSED if absent (ADR-0013 — never silently permit
          // an overwrite). `read` returns null only for a genuine-absent body (bounded-retries transients,
          // throws on auth/decrypt failure), so a real failure fails the write closed.
          const readGrant = st0.grant;
          if (!readGrant) return json({ error: 'interactions grant required to verify dm body write-once — enable messaging for this agent' }, 409);
          const existing = await this.vaultFor(readGrant).read<{ bodyHash?: string }>({ owner: '', resource });
          if (existing?.data?.bodyHash && incomingHash && existing.data.bodyHash !== incomingHash) {
            return json({ error: 'dm body already exists with a different hash — bodies are write-once' }, 409);
          }
          await this.vaultFor(dg).write({ owner: '', resource, data: body.data, classification: 'internal' } as never);
          return json({ ok: true });
        }
        if (op === 'controlevents.append') {
          // spec 323 W2.3 — the person's portable control-plane timeline (`control-events.data`),
          // append-only under the single writer. Server flows (inbox decisions, manifest publish)
          // append via the SEC-010 bridge; the person READS their own via record.get (session-gated).
          const event = body.event;
          if (event === undefined || event === null) return json({ error: 'event required' }, 400);
          return this.serialize(async () => { // ARCH-H1 — serialize the timeline append (many server flows)
            const rows = await this.readDoc<unknown[]>(g, CONTROL_EVENTS_RESOURCE, []);
            rows.push(event);
            await this.writeDoc(g, CONTROL_EVENTS_RESOURCE, rows.slice(-CONTROL_EVENTS_CAP));
            return json({ ok: true });
          });
        }
        // internal.search.query — spec 400 W2 (B5): the harness's search tool reading this object's index in-Worker,
        // for an asker the harness already established as self or steward. The index is a projection; never a record.
        if (op === 'internal.search.query') {
          const idx = ((await this.state.storage.get(SEARCH_INDEX_KEY)) as SearchIndexV1 | undefined) ?? emptyIndex();
          const kinds = Array.isArray(body.kinds) ? (body.kinds as string[]).filter((k): k is SearchDocV1['kind'] => k === 'message' || k === 'topic' || k === 'run') : undefined;
          const hits = searchIndex(idx, String(body.query ?? ''), { ...(kinds?.length ? { kinds } : {}), ...(typeof body.since === 'string' ? { since: body.since } : {}), ...(typeof body.limit === 'number' ? { limit: body.limit } : {}) });
          return json({ ok: true, hits, indexed: idx.order.length });
        }
        // internal.runtime.wake.put — spec 400 W1c: the queue consumer's receipt of one wake, kept DO-local and
        // bounded (a serving-plane ledger: what the steward and the live gate read back; rebuildable, never a record).
        if (op === 'internal.runtime.wake.put') {
          const receipt = body.receipt as WakeReceiptV1 | undefined;
          if (!receipt || receipt.v !== 1 || typeof receipt.messageId !== 'string') return json({ error: 'receipt required' }, 400);
          const ids = ((await this.state.storage.get(RUNTIME_WAKES_KEY)) as string[] | undefined) ?? [];
          const next = [...ids.filter((i) => i !== receipt.messageId), receipt.messageId];
          const evict = next.length > RUNTIME_WAKES_CAP ? next.splice(0, next.length - RUNTIME_WAKES_CAP) : [];
          await this.state.storage.put(`${RUNTIME_WAKE_PREFIX}${receipt.messageId}`, receipt);
          await this.state.storage.put(RUNTIME_WAKES_KEY, next);
          for (const e of evict) await this.state.storage.delete(`${RUNTIME_WAKE_PREFIX}${e}`);
          return json({ ok: true });
        }
        // internal.runtime.pairing.claim / .take — spec 400 W1b: the RUNTIME's two moves on a pairing code, reached
        // through the Worker's public /runtime/pair routes (the code is the credential; the DO decides).
        if (op === 'internal.runtime.pairing.claim' || op === 'internal.runtime.pairing.take') {
          const code = String(body.code ?? '').trim();
          const cur = (await this.state.storage.get(PAIRING_KEY(code))) as PairingStateV1 | undefined;
          if (!cur) return json({ ok: false, error: 'unknown code — mint one at the Home' }, 404);
          if (op === 'internal.runtime.pairing.claim') {
            const r = pairingClaim(cur, { address: String(body.address ?? ''), ...(body.wake !== undefined ? { wake: body.wake } : {}), ...(typeof body.agent === 'string' ? { agent: body.agent } : {}) });
            if (!r.ok) return json({ ok: false, error: r.error }, 409);
            await this.state.storage.put(PAIRING_KEY(code), r.next);
            const { record: _r, ...state } = r.next as PairingStateV1 & { record?: unknown };
            return json({ ok: true, state });
          }
          const r = pairingTake(cur, String(body.address ?? ''));
          if (!r.ok) return json({ ok: false, error: r.error }, 409);
          if (r.next) {
            await this.state.storage.put(PAIRING_KEY(code), r.next);
          }
          return json({ ok: true, state: r.state, ...(r.record ? { record: r.record } : {}) });
        }
        // internal.deliver — append-only merge of a validated envelope (the skill already verified
        // addressing + bodyHash and persisted the body under the delivery grant).
        const envelope = body.envelope as MessageEnvelopeV1 | undefined;
        if (!envelope?.id) return json({ error: 'envelope required' }, 400);
        return this.serialize(async () => { // ARCH-H1 — serialize the inbox merge (many senders → one inbox)
          const doc = (await this.readDoc<Record<string, unknown>>(g, INBOX_RESOURCE, null as never)) ?? { version: 1, envelopes: [], events: [], draftCases: [], caseEvents: [], cards: {} };
          const envs = (doc.envelopes as MessageEnvelopeV1[] | undefined) ?? [];
          const fresh = !envs.some((e) => e.id === envelope.id);
          if (fresh) {
            doc.envelopes = [...envs, envelope];
            doc.events = [
              ...((doc.events as unknown[] | undefined) ?? []),
              { version: 'ap.message.event.v1', messageId: envelope.id, actor: envelope.from, eventType: 'delivered', at: new Date().toISOString() },
            ];
            await this.writeDoc(g, INBOX_RESOURCE, doc);
            // spec 328 §3 — post-commit assistant scan (the A2A ingress). Queued behind this
            // serialize slot, NOT awaited (we hold the mutex); never affects this response.
            this.queueInboxAssistantScan(principal, doc.envelopes as MessageEnvelopeV1[]);
          }
          // Spec 400 W1c — where this member's runtime lives, if its custodian declared one, so the deliverer can
          // WAKE it (a duplicate is not admitted and wakes nothing). Config on this object, never authority.
          const runtimeHost = fresh ? parseRuntimeHost(await this.state.storage.get(RUNTIME_HOST_KEY)) : null;
          // Spec 400 W2 (B5) — searchable from the moment it is admitted: the words the deliverer carried (never read
          // back from the vault here), the sender, the thread. The record is the vault's; this is its shadow.
          if (fresh && typeof body.bodyText === 'string' && body.bodyText.trim()) {
            const from = (String(envelope.from).match(/0x[0-9a-fA-F]{40}$/)?.[0] ?? '').toLowerCase();
            await this.indexForSearch(envelope.id, { kind: 'message', at: envelope.createdAt, snippet: '', ref: { conversationId: envelope.conversationId, messageId: envelope.id, from, ...(typeof body.fromName === 'string' ? { fromName: body.fromName } : {}), ...(envelope.subject ? { title: envelope.subject } : {}) } }, body.bodyText);
          }
          return json({ ok: true, messageId: envelope.id, admitted: fresh, ...(runtimeHost ? { runtimeHost } : {}) });
        });
      } catch (e) {
        return json({ error: e instanceof Error ? e.message : String(e) }, 409);
      }
    }

    // ── Skills — caller = broker-verified Home session (any principal kind), OR a REGISTERED relying
    // app's OIDC id_token. A relying app (e.g. uupg) drives these ops directly over the standard a2a
    // path with the id_token it holds — NOT a Home session (its aud is a client_id, not DEMO_SSO_AUD),
    // so verifyHomeSession is tried first and verifyRelyingIdToken second. Both resolve to the person's
    // SA; AUTHORIZATION is still enforced below by the on-chain steward/member gate. ──
    // ── Spec 400 W2a — THE AGENT'S OWN RAIL, DRIVEN IN-WORKER. `internal.messaging.send` is `messaging.send` with
    //    this principal as the sender and no session: the harness, co-resident, has ALREADY verified a mandate chain
    //    whose root is this agent (a standing grant its custodian signed once → a child the runtime derived for this
    //    intent) and is now performing the act it authorized. The internal marker says "the Worker is calling"; the
    //    mandate said "this agent may". Neither alone reaches here: the public router refuses `internal.*`, and a
    //    session-less `messaging.send` is refused below. Same rail, same wire, same recipient gate as the person's. ──
    const asSelfInternal = op === 'internal.messaging.send';
    if (asSelfInternal && !isInternalCall(request, this.env)) return json({ error: 'internal op — not authorized' }, 403);
    if (asSelfInternal) op = 'messaging.send';
    let gate = asSelfInternal
      ? { ok: true as const, sa: principal as Address, caip: caip10(Number(this.env.CHAIN_ID ?? 84532), principal as Address) }
      : await verifyHomeSession(String(body.session ?? ''), this.env);
    /** The relying app that called, when one did. Null for the person's own Home (spec 341 §4.3b). */
    let skillsClientId: string | null = null;
    if (!gate.ok) {
      const relying = await verifyRelyingIdToken(String(body.session ?? ''), this.env);
      if (relying.ok) { gate = relying; skillsClientId = relying.clientId; }
    }
    if (!gate.ok) return json({ error: gate.error }, gate.status);
    const sessionSa = gate.sa;
    const sessionCaip = gate.caip;

    /**
     * OWNER-ONLY OPS — spec 341 §4.3c, the audit of this block.
     *
     * THE CLASS. Every op here is reachable with a relying id_token, because this block has accepted
     * one since before per-app grants existed. Its self-checks read `sessionSa === principal`, and that
     * is TRUE for any app holding the person's token — the subject IS the person. So "self access only"
     * meant "the person, or anything they ever connected", which is not what it says and not what a
     * person reading it would expect.
     *
     * THE LINE. A relying app AUTHENTICATES as the person; it is not the person. Ops that CONFIGURE the
     * person's agent or write their private records belong to the owner. Ops a relying app legitimately
     * drives — `channels.*`, `directory.*` — are steward/member-gated by a delegation and are the
     * documented use; they are deliberately untouched.
     *
     * WHY THESE, specifically:
     *  · `readgrant.*` — GRANT MANAGEMENT. Left open, any connected app could revoke another app's read
     *    grant (a denial of service against its peers) or install one under a clientId of its choosing.
     *    An app administering the very mechanism that bounds apps is the sharpest edge found here.
     *  · `relationships.*` — person↔org links are PRIVATE vault credentials, never app-readable
     *    (ADR-0025). This is the one with the clearest existing doctrine and no gate enforcing it.
     *  · `inbox.assistant*` — the auto-reply config and the SKILL.md playbook. An app could rewrite what
     *    the person's agent says on their behalf, which is authorship, not access.
     *  · `member.profile.put`, `membership.put` — identity and membership writes.
     *  · `grants.list` — enumerating a person's authority surface.
     *
     * Verified against both live consumers before landing: `uupg` drives `channels.*`, `status` and the
     * `messaging.*` rail; the `~/skills` registry drives none of these. Neither is affected.
     */
    const OWNER_ONLY = new Set([
      'readgrant.put', 'readgrant.list', 'readgrant.revoke',
      'studygrant.put', 'studygrant.list', 'studygrant.revoke',
      'relationships.get', 'relationships.merge',
      'inbox.assistantEnable', 'inbox.assistantDisable', 'inbox.assistantGet',
      'member.profile.put', 'membership.put', 'grants.list',
    ]);
    if (skillsClientId && OWNER_ONLY.has(op)) {
      return json({ error: 'this is the owner’s own operation — an app authenticated as them may not perform it', code: 'owner_only' }, 403);
    }

    const st = ((await this.state.storage.get('state')) ?? {}) as StoredState;
    const grant = st.grant;
    if (!grant) return json({ error: 'no interactions grant — a steward must enable storage for this agent' }, 409);
    if (!this.grantIsCurrent(grant)) return json({ error: 'interactions grant is stale — a steward must re-enable storage (scope widened this wave)' }, 409);
    const audit = buildAuditSink(this.env);

    try {
      if (op === 'org.recordMembership') {
        // THE ORGANIZATION RECORDS WHOM IT ADMITTED — spec 325's OrganizationMembership, in its own
        // vault, keyed `org.membership:member:<sa>` (finding ORG-MEM-1).
        //
        // Membership had no home. A listing is what a member says about THEMSELVES and most members never
        // publish one; an invitation is how somebody came to be admitted, which the T-box files under
        // "Enrollment instruments — NOT membership". So the only complete roster on the estate was a Home
        // KV cache of a record that nothing ever wrote: wipe it and membership is a bereavement rather
        // than a rebuild (ADR-0055). This is that record, in the vault the org's own agent can read —
        // inside the `vault:org.membership:*` scope its grant already carries, so nothing is widened.
        //
        // THREE THINGS KEPT APART, because collapsing any two ships a bug: the invitation is provenance,
        // the ROLE is declarative ("does not authorize execution"), and the DELEGATION is the authority.
        // The record names all three and confers none of them — a reader that treated it as permission
        // would be trusting the organization's note instead of the member's signature (ADR-0041).
        //
        // WHO MAY WRITE IT: the member, for themselves, presenting the grant they just signed. The
        // delegation must be granted TO this principal BY that member — an organization records a
        // membership OF ITSELF and of nobody else. Enforced here rather than only at the Home, because
        // the Home is not the only thing that can reach this DO.
        //
        // AND ONLY AN ORGANIZATION RECORDS ONE (the owner's rule, 2026-10-02; `org.ttl` §2). A `.workspace` agent
        // is a SERVICE that coordinates a workspace and cannot have members; its membership lives on the
        // organization that GOVERNS it. The cheapest thing this object can know about itself without a chain
        // call is the pointer a governed workspace keeps in its own vault (`workspace.governor`, written when
        // the pair is chartered): present, this principal is a workspace agent and the record belongs on its
        // governor — refused by name, so a ceremony that still joins the workspace learns where to join. A
        // legacy workspace with no pointer is indistinguishable here from an organization and keeps writing
        // its own records, which is the fallback the rule allows. (The DO does not know its own typed name;
        // learning it is a naming-service read, and a membership write must not cost a chain call.)
        const record = body.record as {
          memberAgent?: string; organizationAgent?: string;
          roleAssignment?: { materializedByDelegation?: { delegate?: string; delegator?: string } };
        } | undefined;
        const member = String(record?.memberAgent ?? '').toLowerCase();
        if (!record || !/^0x[0-9a-f]{40}$/.test(member)) return json({ error: 'record.memberAgent required' }, 400);
        if (member !== sessionSa.toLowerCase()) {
          return json({ error: 'a member records their own membership — the session must be the member' }, 403);
        }
        if (String(record.organizationAgent ?? '').toLowerCase() !== principal.toLowerCase()) {
          return json({ error: 'a membership record belongs to the organization it names' }, 403);
        }
        const wire = record.roleAssignment?.materializedByDelegation;
        if (!wire) return json({ error: 'a membership is materialized by a delegation; none was presented' }, 400);
        if (String(wire.delegate ?? '').toLowerCase() !== principal.toLowerCase()) {
          return json({ error: 'the membership delegation must be granted TO this organization' }, 403);
        }
        if (String(wire.delegator ?? '').toLowerCase() !== member) {
          return json({ error: 'the membership delegation must be granted BY the member it records' }, 403);
        }
        const governor = governorOf(await this.readDoc<unknown>(grant, WORKSPACE_GOVERNOR_RECORD, null).catch(() => null));
        if (governor && governor !== principal) {
          return json({ ok: false, code: 'not_an_organization', error: `this is a workspace agent, and a workspace holds no members — membership is recorded on the organization that governs it (${governor})`, governedBy: governor }, 409);
        }
        return this.serialize(async () => {
          // THE ROLE IS THE ORGANIZATION'S STATEMENT, NOT THE MEMBER'S (spec 427 §3.3, invariant 3). The member
          // writes this record, for themselves; what they DO here was decided by whoever invited them. So the role
          // is never taken from the body: it is read from the organization's own records — a role a steward set on
          // a standing membership, else the offer on the invitation it stored for this member, else the plain
          // member — and whatever the body claimed is only CHECKED against that. A member cannot join as a role
          // they were not offered, and an older Home that still sends the constant 'member' records the right one.
          // The role authorizes nothing either way (324): no gate in this file reads it.
          const memberKey = `org.membership:member:${member}`;
          const claimed = (record.roleAssignment ?? {}) as { assignedRole?: unknown; roleDefinitionId?: unknown };
          const claimsRole = (!!claimed.assignedRole && String(claimed.assignedRole).toLowerCase() !== PLAIN_MEMBER) || !!claimed.roleDefinitionId;
          let invite: { orgRole?: unknown; invitedBy?: unknown; status?: unknown } | null = null;
          let inviteReadable = true;
          // The invitation is read under the DELIVERY wire: `org.invite:*` is in that grant's record scope and in
          // none the interactions grant carries (the same wire `invite.put` wrote it under).
          try { invite = await this.readDoc<{ orgRole?: unknown; invitedBy?: unknown; status?: unknown } | null>(st.deliveryGrant ?? grant, `org.invite:agent:${member}`, null); } catch { inviteReadable = false; }
          // "Could not look" is not "was not offered": a claimed role is refused as unverifiable, never as a lie.
          if (!inviteReadable && claimsRole) return json({ ok: false, code: 'role_unverifiable', error: 'could not read the invitation this role is recorded from — try again' }, 503);
          const existing = await this.readDoc<{ endedAt?: unknown; roleAssignment?: Partial<AssignedRoleFields> | null } | null>(grant, memberKey, null).catch(() => null);
          const role = resolveAssignedRole({ claimed, invite, existing, now: new Date().toISOString() });
          if (!role.ok) return json({ ok: false, code: role.code, error: role.error }, 403);
          const stamped = { ...record, roleAssignment: { ...withoutRoleFields(record.roleAssignment as Record<string, unknown>), ...role.fields } };
          await this.writeDoc(grant, memberKey, stamped);
          // The room says so: a new member is announced in the Welcome topic — best-effort, never gating, and
          // AFTER the answer: a join ceremony waited on the topic being created, read and appended to (several
          // vault operations) before the person could be told they were in.
          const asRole = role.fields.roleName ? ` as ${role.fields.roleName}` : '';
          const announce = async () => { try { await this.postWelcome(grant, principal, `👋 ${await this.boardNameFor(grant, member)} joined${asRole}.`, true); } catch { /* the welcome is not the membership */ } };
          // A test's fake state has no `waitUntil`; there the line is simply awaited.
          const later = (this.state as { waitUntil?: (p: Promise<unknown>) => void }).waitUntil;
          if (typeof later === 'function') later.call(this.state, announce()); else await announce();
          return json({ ok: true, member, role: role.fields.assignedRole, ...(role.fields.roleName ? { roleName: role.fields.roleName } : {}), ...(role.fields.roleDefinitionId ? { roleDefinitionId: role.fields.roleDefinitionId } : {}), roleFrom: role.from });
        });
      }
      if (op === 'org.setMemberRole') {
        // A STEWARD CHANGES WHAT A MEMBER DOES HERE (spec 427 §3.3). The same record, the same key: the role fields
        // are replaced, the delegation that materializes the membership and the household facets are kept. `orgRole:
        // null` puts the member back to the plain role. It is a statement and confers nothing — the access a role
        // needs is issued (or revoked) by its own ceremony, and the pack it offers is the member's to accept: nothing
        // here reaches into anybody's playbook, and nothing could (invariant 2).
        //
        // WHO: a steward of this organization, like removal (`org.endMembership`). A member does not promote themself.
        const member = String(body.member ?? '').toLowerCase();
        if (!/^0x[0-9a-f]{40}$/.test(member)) return json({ error: 'member required' }, 400);
        if (!(await this.isSteward(principal, sessionSa, body.stewardship as IncomingDelegation | undefined))) {
          return json({ error: 'a member\u2019s role is set by a steward of the organization' }, 403);
        }
        const now = new Date().toISOString();
        let fields: AssignedRoleFields;
        if (body.orgRole === null || body.orgRole === undefined) {
          fields = { assignedRole: PLAIN_MEMBER, assignedBy: sessionSa.toLowerCase(), assignedAt: now, roleSetAt: now };
        } else {
          const parsed = parseRoleOffer(body.orgRole);
          if (!parsed.ok) return json({ ok: false, code: 'invalid_role_offer', error: parsed.error }, 400);
          fields = { ...roleFieldsFromOffer(parsed.offer, sessionSa, now), roleSetAt: now };
        }
        return this.setMemberRole(grant, principal, member, fields, sessionSa, audit);
      }
      if (op === 'org.membership.mine') {
        // WHAT THIS ORGANIZATION RECORDS OF ME (spec 427 §5.3). A person cannot read an organization's vault and
        // does not need to: the session says who is asking and the key is DERIVED from it, never supplied — the
        // same property as `invite.claim`. It answers that member's record and nothing else, ended or not (a
        // person's Home drops a role's pack when the membership it came from has ended, and must be able to see
        // that it has). The delegation on the record is the member's own; it is not echoed — the role is the point.
        return json(await this.membershipAnswer(grant, principal, sessionSa.toLowerCase()));
      }
      if (op === 'org.endMembership') {
        // THE ORGANIZATION'S RECORD SAYS WHEN A MEMBERSHIP ENDED (spec 324 §11). Removal and leaving cleared every
        // projection — the listing, the member link, the grant index — and left this record untouched, so the org's
        // own agent kept counting a removed member: the roster listed them, and an invitation back was refused as
        // "already holds organization membership". The record is KEPT and stamped (who was here then is history);
        // every reader skips a record with `endedAt`.
        //
        // WHO MAY END IT: the member, for themselves (leaving), or a steward of this organization (removal) — the
        // same two parties whose acts end a membership. Nobody else writes an organization's roster.
        const member = String(body.member ?? '').toLowerCase();
        if (!/^0x[0-9a-f]{40}$/.test(member)) return json({ error: 'member required' }, 400);
        const self = member === sessionSa.toLowerCase();
        if (!self && !(await this.isSteward(principal, sessionSa, body.stewardship as IncomingDelegation | undefined))) {
          return json({ error: 'a membership is ended by the member or by a steward of the organization' }, 403);
        }
        const endReason = self ? 'left' : 'removed';
        return this.serialize(async () => {
          const key = `org.membership:member:${member}`;
          const rec = await this.readDoc<Record<string, unknown> | null>(grant, key, null);
          if (!rec) return json({ ok: true, member, ended: false, reason: 'no membership record' });
          if (typeof rec.endedAt === 'string' && rec.endedAt) return json({ ok: true, member, ended: true, already: true });
          await this.writeDoc(grant, key, { ...rec, endedAt: new Date().toISOString(), endReason });
          await audit.write({ id: crypto.randomUUID(), timestamp: new Date().toISOString(), action: 'interactions.org.membership.end', outcome: 'success', actor: { type: 'user', id: sessionSa }, subject: { type: 'membership', id: member } });
          return json({ ok: true, member, ended: true });
        });
      }
      if (op === 'directory.publish') {
        const listing = body.listing as DirectoryListingV1 | undefined;
        if (!listing) return json({ error: 'listing required' }, 400);
        const errors = validateDirectoryListing(listing);
        if (errors.length > 0) return json({ error: `invalid listing: ${errors.join(', ')}` }, 400);
        if (listing.subject.toLowerCase() !== sessionCaip.toLowerCase()) {
          // A steward publishing ANOTHER subject's ORG listing (spec 313 §4 Networks): the presented
          // stewardship wire must be delegated BY the listing subject to the session SA.
          const subjAddr = listing.subject.match(/0x[0-9a-fA-F]{40}$/)?.[0];
          const w = body.subjectStewardship as IncomingDelegation | undefined;
          const ok = !!subjAddr && (await this.isSteward(subjAddr, sessionSa, w));
          if (!ok) return json({ error: 'listing subject must be the session principal (or present its stewardship wire)' }, 403);
          // DIR-INJECT-1 — proving you steward the SUBJECT is NOT enough: `principal` here is the DIRECTORY
          // OWNER (this org shard) and `listing.context.id`/communityId is caller-chosen, so without this
          // check any steward of any org could inject their org's card into an arbitrary victim org's
          // membership index (the doc `memberName` trusts) — the SEC-H1 self-publish gate reached through the
          // cross-subject branch. The directory OWNER must also have authorized this caller.
          const ownerAuthorized =
            (await this.isSteward(principal, sessionSa, body.stewardship as IncomingDelegation | undefined)) ||
            (await this.hasMemberAccess(principal, sessionSa, body.memberAccess as IncomingDelegation | undefined));
          if (!ownerAuthorized) return json({ error: 'this organization has not authorized you to publish listings into its directory' }, 403);
        } else {
          // SELF-publish (join / update own listing). SEC-H1: a self-signed listing is NOT enough —
          // the ORG must have authorized this member. Require the org→you member-access grant (from an
          // invite), OR prove you steward this org (the creator's / steward's own self-card).
          const authorized =
            (await this.hasMemberAccess(principal, sessionSa, body.memberAccess as IncomingDelegation | undefined)) ||
            (await this.isSteward(principal, sessionSa, body.stewardship as IncomingDelegation | undefined));
          if (!authorized) return json({ error: 'this organization has not authorized you to join — an invite (member-access grant) or stewardship is required' }, 403);
        }
        const { proof, ...draft } = listing;
        const digest = await sha256Hex32(canonicalizeMessage(draft));
        const proofSubject = (listing.subject.match(/0x[0-9a-fA-F]{40}$/)?.[0] ?? sessionSa) as Address;
        if (!(await this.erc1271(proofSubject, digest as Hex, proof.signature as Hex))) return json({ error: 'listing signature failed ERC-1271 verification' }, 403);
        // DIR-INJECT-1 — the replay/tombstone/dedup key is the LISTING SUBJECT, not the caller session. For a
        // self-publish these are equal; for a steward-of-subject publish they differ, and keying on the caller
        // let a tombstoned (subject-keyed) listing be re-injected and duplicate subject rows accumulate.
        const me = listing.subject.toLowerCase();
        // NEW-M1 (ARCH-H1 residual) — the directory doc + st.subjects RMW is a shared-doc write across
        // concurrent joins; serialize it (re-reading both inside the lock) so two simultaneous joins can't
        // lost-update each other's listing. The expensive ERC-1271 proof stays outside the lock.
        return this.serialize(async () => {
          const fresh = ((await this.state.storage.get('state')) ?? {}) as StoredState;
          // Replay guard: monotonic publishedAt per subject; publishing clears any tombstone (rejoin).
          const prev = fresh.subjects?.[me]?.publishedAt;
          if (prev && Date.parse(listing.publishedAt) <= Date.parse(prev)) return json({ error: 'stale listing (publishedAt must be monotonic)' }, 409);
          const rows = (await this.readDoc<IndexedListing[]>(grant, DIRECTORY_RESOURCE, [])).filter((l) => l.listing.subject.toLowerCase() !== me);
          rows.push({ listing, label: String(body.label ?? '') });
          await audit.write({ id: crypto.randomUUID(), timestamp: new Date().toISOString(), action: 'interactions.directory.publish', outcome: 'success', actor: { type: 'user', id: sessionSa }, subject: { type: 'listing', id: me } });
          await this.writeDoc(grant, DIRECTORY_RESOURCE, rows);
          fresh.subjects = { ...(fresh.subjects ?? {}), [me]: { publishedAt: listing.publishedAt } };
          await this.state.storage.put('state', fresh);
          return json({ ok: true });
        });
      }

      if (op === 'directory.revoke') {
        const me = sessionCaip.toLowerCase();
        const rows = (await this.readDoc<IndexedListing[]>(grant, DIRECTORY_RESOURCE, [])).filter((l) => l.listing.subject.toLowerCase() !== me);
        await audit.write({ id: crypto.randomUUID(), timestamp: new Date().toISOString(), action: 'interactions.directory.revoke', outcome: 'success', actor: { type: 'user', id: sessionSa }, subject: { type: 'listing', id: me } });
        await this.writeDoc(grant, DIRECTORY_RESOURCE, rows);
        st.subjects = { ...(st.subjects ?? {}), [me]: { publishedAt: st.subjects?.[me]?.publishedAt ?? new Date().toISOString(), tombstoned: true } };
        this.presenceMemo.clear();
        await this.state.storage.put('state', st);
        return json({ ok: true });
      }

      if (op === 'directory.remove') {
        // STEWARD removal of another member's listing (spec 321 W3 continuity under the DO): the
        // caller presents the stewardship wire; the subject's listing is dropped + tombstoned so a
        // replayed old listing cannot re-enter (spec 322 §4).
        const steward = await this.isSteward(principal, sessionSa, body.stewardship as IncomingDelegation | undefined);
        if (!steward) return json({ error: 'stewardship proof required' }, 403);
        const subject = String(body.subject ?? '').toLowerCase();
        if (!subject) return json({ error: 'subject required' }, 400);
        const rows = (await this.readDoc<IndexedListing[]>(grant, DIRECTORY_RESOURCE, [])).filter((l) => !l.listing.subject.toLowerCase().endsWith(subject));
        await audit.write({ id: crypto.randomUUID(), timestamp: new Date().toISOString(), action: 'interactions.directory.remove', outcome: 'success', actor: { type: 'user', id: sessionSa }, subject: { type: 'listing', id: subject } });
        await this.writeDoc(grant, DIRECTORY_RESOURCE, rows);
        const key = Object.keys(st.subjects ?? {}).find((k) => k.endsWith(subject)) ?? subject;
        st.subjects = { ...(st.subjects ?? {}), [key]: { publishedAt: st.subjects?.[key]?.publishedAt ?? new Date().toISOString(), tombstoned: true } };
        this.presenceMemo.clear();
        await this.state.storage.put('state', st);
        return json({ ok: true });
      }

      if (op === 'directory.setLocalName') {
        const presence = await this.communityPresence(grant, principal, sessionSa, sessionCaip, body);
        if (!presence.admitted) {
          return json({ error: 'join this community first — a member-access grant, a current directory listing, or stewardship is required' }, 403);
        }
        const localName = this.normalizeLocalName(body.displayName);
        if (!localName) {
          return json({ error: 'choose a name this community will know you by — not an address', code: 'local_name_required' }, 400);
        }
        return this.serialize(async () => {
          const names = await this.readLocalNames(grant);
          names[sessionSa.toLowerCase()] = localName;
          await this.writeDoc(grant, LOCAL_NAMES_RESOURCE, names);
          return json({ ok: true, you: localName });
        });
      }

      if (op === 'directory.list') {
        const presence = await this.communityPresence(grant, principal, sessionSa, sessionCaip, body);
        if (!presence.admitted) {
          return json({ error: 'join this community first — a member-access grant, a current directory listing, or stewardship is required' }, 403);
        }
        const now = new Date().toISOString();
        const rows = (await this.readDoc<IndexedListing[]>(grant, DIRECTORY_RESOURCE, [])).filter((l) => isListingCurrent(l.listing, now));
        const localNames = await this.readLocalNames(grant);
        // The member's CURRENT naming-service name rides each listing (live reverse resolution,
        // null for the nameless) — so a roster can show who a member is to the world as well as
        // who they are here, without every consumer re-running the same chain reads.
        const subjects = rows.map((r) => String((r.listing as { subject?: string } | undefined)?.subject ?? '').match(/0x[0-9a-fA-F]{40}/)?.[0] ?? '');
        // THE ROLE EACH MEMBER HOLDS HERE rides beside their listing (spec 427 §3.4) — beside, never inside: the
        // listing is what the member signed about THEMSELVES, the role is what the ORGANIZATION records of them, and
        // a roster that took the role from the listing would let anybody title themselves. One batch read of the
        // membership records for the people listed, alongside the name resolution; a failed read costs the roles,
        // never the roster. Words for people to read — nothing here or anywhere gates on them.
        const rolesOf = async (): Promise<Record<string, { assignedRole: string; roleName?: string; roleDefinitionId?: string }>> => {
          const keys = [...new Set(subjects.filter(Boolean).map((a) => `org.membership:member:${a.toLowerCase()}`))].slice(0, 200);
          if (!keys.length) return {};
          try {
            const got = (await this.mcpVaultTool(grant, 'get_vault_records', { recordTypes: keys }).then((r) => r.json())) as { records?: Record<string, unknown> };
            const out: Record<string, { assignedRole: string; roleName?: string; roleDefinitionId?: string }> = {};
            for (const [k, v] of Object.entries(got.records ?? {})) {
              const rec = v as { endedAt?: unknown; roleAssignment?: Partial<AssignedRoleFields> } | null;
              const ra = rec && !rec.endedAt ? rec.roleAssignment : null;
              if (!ra?.assignedRole || ra.assignedRole === PLAIN_MEMBER) continue;
              out[k.slice('org.membership:member:'.length)] = { assignedRole: ra.assignedRole, ...(ra.roleName ? { roleName: ra.roleName } : {}), ...(ra.roleDefinitionId ? { roleDefinitionId: ra.roleDefinitionId } : {}) };
            }
            return out;
          } catch { return {}; }
        };
        const [publicNames, roles] = await Promise.all([this.resolvePublicNames(subjects), rolesOf()]);
        const listings = rows.map((r) => {
          const subject = String((r.listing as { subject?: string } | undefined)?.subject ?? '');
          const addr = (subject.match(/0x[0-9a-fA-F]{40}/)?.[0] ?? '').toLowerCase();
          const localName = addr ? localNames[addr] : undefined;
          const publicName = addr ? (publicNames[addr] ?? null) : null;
          const role = addr ? roles[addr] : undefined;
          if (!r.listing) return r;
          return {
            ...r,
            listing: { ...r.listing, ...(localName ? { localName } : {}), ...(publicName ? { publicName } : {}) },
            ...(role ? { role } : {}),
          };
        });
        return json({ ok: true, listings, you: presence.you ?? '' });
      }

      if (op === 'channels.list' || op === 'channels.read') {
        // A read is a WAVE, not a chain. The presence proofs, the index, the invitations and the one topic's
        // messages are independent documents; read in series (as they were) a `channels.read` was seven
        // vault round trips end to end — five seconds on the estate — and a poll paid it every three
        // seconds. The admission decision still gates what is RETURNED: a refused caller gets the 403 and
        // nothing of what was read alongside it (every read is under the org's grant, as before).
        const topicId = op === 'channels.read' && typeof body.channelId === 'string' ? body.channelId : null;
        opMs.admitted = Date.now() - opT0;
        const [presence, index0, invitations, messages] = await Promise.all([
          timedOp('presence', this.communityPresence(grant, principal, sessionSa, sessionCaip, body)),
          timedOp('index', this.readDoc<ChannelV1[]>(grant, CONVERSATION_INDEX_RESOURCE, [])),
          timedOp('invitations', this.readDoc<DiscussionInvitationRowV1[]>(grant, DISCUSSION_INVITATIONS_RESOURCE, [])),
          topicId ? timedOp('topic', this.readDoc<{ envelope: MessageEnvelopeV1; authorName: string }[]>(grant, TOPIC_RESOURCE(topicId), [])) : Promise.resolve([] as { envelope: MessageEnvelopeV1; authorName: string }[]),
        ]);
        if (!presence.admitted) {
          return json({ error: 'join this community first — a member-access grant, a current directory listing, or stewardship is required' }, 403);
        }
        const steward = presence.steward;
        // Every board opens with a Welcome topic (created here if the organization has none yet). The index
        // just read answers whether one exists; only a board without one pays the create.
        const index = index0.some((c) => c.title.trim().toLowerCase() === 'welcome')
          ? index0
          : await this.ensureWelcomeTopic(grant, principal).then(() => this.readDoc<ChannelV1[]>(grant, CONVERSATION_INDEX_RESOURCE, [])).catch(() => index0);
        // Conversation/topic split (§10): descriptors from conversation.index; ONE topic's messages from its own doc.
        const bodies: Record<string, string> = {};
        const pendingInvites = invitations
          .filter((i) => i.invitedAgent.toLowerCase() === sessionSa.toLowerCase() && i.status === 'invited')
          .map((i) => i.topicId);
        const invited = new Set(pendingInvites);
        // Topic participation: a viewer (an org MEMBER — the gate above) sees every OPEN topic plus only the
        // RESTRICTED topics they PARTICIPATE in (steward/custodian sees all). A pending invitee sees that
        // topic so they can accept — otherwise the invite exists and the room looks empty. Legacy
        // `visibility` records are mapped to participationPolicy on read (public→open, private→restricted).
        let wire = index
          .filter((c) => canSeeChannel(c, sessionSa, steward) || invited.has(c.descriptor.id))
          // spec 340 W12 — a topic IS an Interaction, so it is served as one. The view is a PROJECTION
          // over what the board already stores (the id derives from `descriptor.id`, the mode from
          // `participationPolicy`), so this adds a field to the wire and nothing to the vault: no
          // migration, and no second copy that could disagree with the descriptor it came from.
          .map((c) => ({
            ...c,
            participationPolicy: channelParticipationPolicy(c),
            interaction: interactionViewOfChannel(c),
            messages: [] as { envelope: MessageEnvelopeV1; authorName: string }[],
          }));
        if (topicId) {
          wire = wire.map((c) => (c.descriptor.id === topicId ? { ...c, messages } : c));
          // Bodies load at the envelope's OWN resource (channel namespace) — never re-normalized.
          // ONE batched round-trip for the whole topic (was one delegated read PER MESSAGE — the
          // O(board size) per-poll amplification behind the 2026-07-18 "auth failed" regression).
          // `after: <messageId>` is a poller's cursor: a topic whose LAST entry is still that message
          // has nothing new to show, so the bodies hop is not paid — the envelopes still come back, so
          // the caller sees the same topic it saw; only the bytes it already holds are not re-read.
          // With a cursor the poller already holds every body up to it, so only the NEWER envelopes are
          // fetched (each body is its own record — `topicBodyResource(channel, message)` — so the batch is
          // exactly those). A topic that has been asked a hundred questions was re-fetching a hundred
          // briefs on every poll; a cursor unknown to the topic is treated as no cursor.
          const after = typeof body.after === 'string' ? body.after : '';
          const at = after ? messages.findIndex((m) => m.envelope.id === after) : -1;
          const fresh = at >= 0 ? messages.slice(at + 1) : messages;
          if (fresh.length > 0) Object.assign(bodies, await timedOp('bodies', this.readTopicBodies(grant, fresh.map((m) => m.envelope))));
        }
        return json(withMs({ ok: true, channels: wire, bodies, you: presence.you ?? '', steward, invitedTopicIds: pendingInvites }));
      }

      if (op === 'channels.create') {
        const presence = await this.communityPresence(grant, principal, sessionSa, sessionCaip, body);
        if (!presence.admitted) {
          return json({ error: 'join this community first — a member-access grant, a current directory listing, or stewardship is required' }, 403);
        }
        if (!presence.you) {
          return json({ error: 'choose a name this community will know you by before opening a topic', code: 'local_name_required' }, 403);
        }
        const name = presence.you;
        const steward = presence.steward;
        // Participation policy: `open` (every org member participates — derived, no stored list) or
        // `restricted` (invite-only). Legacy callers still say visibility public/private. Any member may
        // create an OPEN topic; creating a RESTRICTED one is a facilitator act — steward/custodian only.
        const restricted = body.participationPolicy === 'restricted' || body.visibility === 'private';
        if (restricted && !steward) return json({ error: 'only the organization custodian may create a restricted topic (facilitators are then invited per topic)' }, 403);
        return this.serialize(async () => { // ARCH-H1 — the conversation.index RMW is a shared-doc write; serialize it too
          const index = await this.readDoc<ChannelV1[]>(grant, CONVERSATION_INDEX_RESOURCE, []);
          const r = createBoardChannel(index, {
            contextId: principal, owner: sessionCaip as ChannelV1['descriptor']['owner'], title: String(body.title ?? ''), createdBy: name ?? 'Steward',
            participationPolicy: restricted ? 'restricted' : 'open',
            members: Array.isArray(body.members) ? (body.members as unknown[]).map((m) => String(m)) : [],
            creatorSa: sessionSa,
          });
          if (!r.ok) return json({ error: r.error }, r.error.includes('already exists') ? 409 : 400);
          if (restricted) {
            // The creator is the topic's first FACILITATOR — an asserted participation (self-accepted;
            // the creation ceremony is its own consent). Seeds the situation doc the ops below extend.
            const now = new Date().toISOString();
            const rows: DiscussionParticipationRowV1[] = [{
              personSA: sessionSa.toLowerCase(), ...(name ? { personName: name } : {}), role: 'facilitator',
              situationRef: `sit_dp_${crypto.randomUUID()}`, invitationRef: 'creator', acceptedAt: now, status: 'active',
            }];
            await this.writeDoc(grant, TOPIC_PARTICIPATION_RESOURCE(r.channel.descriptor.id), rows);
          }
          await audit.write({ id: crypto.randomUUID(), timestamp: new Date().toISOString(), action: 'interactions.channels.create', outcome: 'success', actor: { type: 'user', id: sessionSa }, subject: { type: 'channel', id: r.channel.descriptor.id } });
          await this.writeDoc(grant, CONVERSATION_INDEX_RESOURCE, index); // index holds descriptors only (messages stay [])
          return json({ ok: true, channelId: r.channel.descriptor.id });
        });
      }

      if (op === 'channels.post') {
        // The presence proofs (a listing read + ERC-1271, the steward wire's two chain reads) and the two
        // board documents are independent: the proofs start now and are JOINED under the write lock, before
        // anything is appended or written. Nothing of the board reaches a caller the proofs refuse.
        opMs.admitted = Date.now() - opT0;
        const presenceP = timedOp('presence', this.communityPresence(grant, principal, sessionSa, sessionCaip, body));
        // Board split (W3): only the ONE channel doc is read + rewritten — same-channel conflicts only.
        const channelId = String(body.channelId ?? '');
        return this.serialize(async () => { // ARCH-H1 — serialize the channel append (many members → one channel doc)
          opMs.lock = Date.now() - opT0;
          const [presence, index, messages] = await Promise.all([
            presenceP,
            timedOp('index', this.readDoc<ChannelV1[]>(grant, CONVERSATION_INDEX_RESOURCE, [])),
            timedOp('topic', this.readDoc<{ envelope: MessageEnvelopeV1; authorName: string }[]>(grant, TOPIC_RESOURCE(channelId), [])),
          ]);
          if (!presence.admitted) {
            return json({ error: 'join this community first — a member-access grant, a current directory listing, or stewardship is required' }, 403);
          }
          if (!presence.you) {
            return json({ error: 'choose a name this community will know you by before posting', code: 'local_name_required' }, 403);
          }
          const name = presence.you;
          // A named member posts as themselves; an unnamed steward still facilitates restricted topics.
          const posterSteward = !presence.listed && presence.steward;
          const entry = index.find((c) => c.descriptor.id === channelId);
          if (!entry) return json({ error: 'unknown channel' }, 404);
          // Post gate: OPEN topic ⇒ the org-member gate above suffices (participation is derived from
          // membership). RESTRICTED topic ⇒ only its PARTICIPANTS post — the members[] projection of the
          // accepted DiscussionParticipation situations (the steward/custodian facilitates every topic).
          if (!canSeeChannel(entry, sessionSa, posterSteward)) return json({ error: 'not a participant of this restricted topic — ask a facilitator for an invitation' }, 403);
          const composed: ChannelV1[] = [{ ...entry, messages }];
          const r = await appendBoardPost(composed, { channelId, from: sessionCaip as AnyMessageEnvelope['from'], authorName: name ?? 'Steward', bodyText: String(body.bodyText ?? '') });
          if (!r.ok) return json({ error: r.error }, r.error === 'unknown channel' ? 404 : 400);
          await timedOp('audit', audit.write({ id: crypto.randomUUID(), timestamp: r.envelope.createdAt, action: 'interactions.channels.post', outcome: 'success', actor: { type: 'user', id: sessionSa }, subject: { type: 'channel-post', id: r.envelope.id } }));
          const store = createVaultMessageBodyStore(this.vaultFor(grant), principal);
          // Channel bodies live in the CHANNEL namespace (the envelope's own resource — closes FAB-SSO-2).
          await timedOp('putBody', store.putBody({ messageId: r.envelope.id, bytes: new TextEncoder().encode(String(body.bodyText ?? '').trim()), contentType: 'text/plain', classification: 'internal', resource: r.envelope.body.resource }));
          await timedOp('writeTopic', this.writeDoc(grant, TOPIC_RESOURCE(channelId), composed[0]!.messages));
          await this.indexForSearch(r.envelope.id, { kind: 'topic', at: r.envelope.createdAt, snippet: '', ref: { org: principal, channelId, messageId: r.envelope.id, from: sessionSa.toLowerCase(), fromName: name ?? 'Steward', title: entry.title } }, String(body.bodyText ?? '').trim());
          // spec 327 §3 — post-commit assistant trigger: fire-and-forget AFTER the member's post is
          // durable; a failed/limited dispatch is audited + dropped, never affecting this response.
          if (assistantTrigger(entry, { from: sessionCaip as AnyMessageEnvelope['from'], bodyText: String(body.bodyText ?? '') })) {
            this.dispatchAssistant({ entry, channelId, principal, triggerAuthor: name ?? 'Steward', triggerAuthorSa: sessionSa.toLowerCase(), triggerBody: String(body.bodyText ?? '').trim() });
          }
          // Spec 400 W2 (B3) — every MEMBER AGENT the post names hears it: the mention is admitted into that
          // member's inbox on the topic's thread, post-commit, fire-and-forget (audited, never queued).
          this.dispatchMentions({ entry, channelId, principal, grant, posterCaip: sessionCaip, posterName: name ?? 'Steward', bodyText: String(body.bodyText ?? '').trim(), messageId: r.envelope.id });
          await timedOp('recordOp', this.recordOperation(body, 'send', r.envelope.id));
          return json(withMs({ ok: true, messageId: r.envelope.id }));
        });
      }

      if (op === 'channels.react') {
        // An emoji reaction is a TOGGLE on one message — the lightest utterance a member has.
        // Same doors as posting (org member on an OPEN topic; participants only on a RESTRICTED
        // one), but NO display name required: a reaction carries the reactor's SA, not a byline.
        const presence = await this.communityPresence(grant, principal, sessionSa, sessionCaip, body);
        if (!presence.admitted) {
          return json({ error: 'join this community first — a member-access grant, a current directory listing, or stewardship is required' }, 403);
        }
        const channelId = String(body.channelId ?? '');
        const messageId = String(body.messageId ?? '');
        const emoji = String(body.emoji ?? '').trim();
        if (!channelId || !messageId) return json({ error: 'channelId and messageId required' }, 400);
        if (!emoji || emoji.length > 16) return json({ error: 'emoji required (a short glyph, not a sentence)' }, 400);
        const reactorSteward = !presence.listed && presence.steward;
        return this.serialize(async () => { // same single-writer rule as post: one channel doc, many members
          const index = await this.readDoc<ChannelV1[]>(grant, CONVERSATION_INDEX_RESOURCE, []);
          const entry = index.find((c) => c.descriptor.id === channelId);
          if (!entry) return json({ error: 'unknown channel' }, 404);
          if (!canSeeChannel(entry, sessionSa, reactorSteward)) return json({ error: 'not a participant of this restricted topic — ask a facilitator for an invitation' }, 403);
          type RowWithReactions = { envelope: MessageEnvelopeV1; authorName: string; reactions?: Record<string, string[]> };
          const messages = await this.readDoc<RowWithReactions[]>(grant, TOPIC_RESOURCE(channelId), []);
          const row = messages.find((m) => m.envelope.id === messageId);
          if (!row) return json({ error: 'unknown message' }, 404);
          const me = sessionSa.toLowerCase();
          const cur = { ...(row.reactions ?? {}) };
          const holders = (cur[emoji] ?? []).map((s) => s.toLowerCase());
          if (holders.includes(me)) {
            const rest = holders.filter((s) => s !== me);
            if (rest.length) cur[emoji] = rest;
            else delete cur[emoji];
          } else {
            // Bound the doc: 20 distinct emoji per message is a conversation, not a keyboard test.
            if (!cur[emoji] && Object.keys(cur).length >= 20) return json({ error: 'this message already carries 20 distinct reactions' }, 400);
            cur[emoji] = [...holders, me];
          }
          if (Object.keys(cur).length) row.reactions = cur;
          else delete row.reactions;
          const added = !holders.includes(me);
          await this.writeDoc(grant, TOPIC_RESOURCE(channelId), messages);
          // Spec 400 W2 (B7) — A REACTION IS A TRIGGER SOURCE. An emoji ADDED to a post fires the post's AUTHOR's
          // `message` triggers with profile `reaction` (a removal fires nothing): a 👍 on the coordinator's proposal is
          // the lightest "go" a member has, and the playbook says what it means. Post-commit, fire-and-forget, the
          // author's own object, marker-gated; the org itself and persons are authors too — a person's agent hears
          // it through its own triggers. Never authority: what the author may do about it is its grant.
          if (added) this.dispatchReaction({ entry, channelId, principal, author: row.envelope.from, messageId, emoji, by: sessionSa.toLowerCase(), byName: presence.you ?? null });
          await audit.write({ id: crypto.randomUUID(), timestamp: new Date().toISOString(), action: 'interactions.channels.react', outcome: 'success', actor: { type: 'user', id: sessionSa }, subject: { type: 'channel-post', id: messageId } });
          return json({ ok: true, messageId, reactions: row.reactions ?? {} });
        });
      }

      // ── spec 334 §6 auto-work switch — the single per-principal toggle behind "the agent does the
      //    work". Self (a person's own DO) OR steward (an org's DO) may set it; anyone visible reads
      //    it. Config is the canonical VAULT record; the DO flag is the O(1) gate cache the trigger
      //    paths read (written LAST, like the inbox assistant flag — never flags an unwritten config).
      if (op === 'autowork.get' || op === 'autowork.enable' || op === 'autowork.disable') {
        const self = sessionSa.toLowerCase() === principal;
        if (op === 'autowork.get') {
          const cfg = await this.readDoc<AutoWorkV1 | null>(grant, AUTO_WORK_RESOURCE, null);
          return json({ ok: true, enabled: cfg?.enabled === true });
        }
        const allowed = self || (await this.isSteward(principal, sessionSa, body.stewardship as IncomingDelegation | undefined));
        if (!allowed) return json({ error: 'only the principal (or an organization steward) may change auto-work' }, 403);
        const enabled = op === 'autowork.enable';
        const now = new Date().toISOString();
        const cfg: AutoWorkV1 = { version: 'ap.auto-work.v1', enabled, enabledBy: sessionSa.toLowerCase(), enabledAt: now };
        await audit.write({ id: crypto.randomUUID(), timestamp: now, action: `interactions.${op}`, outcome: 'success', actor: { type: 'user', id: sessionSa }, subject: { type: 'auto-work', id: principal } });
        await this.writeDoc(grant, AUTO_WORK_RESOURCE, cfg);
        if (enabled) await this.state.storage.put(AUTO_WORK_FLAG_KEY, true);
        else await this.state.storage.delete(AUTO_WORK_FLAG_KEY);
        return json({ ok: true, enabled });
      }

      // ── spec 334 §3 — the coordination serving plane (`endeavor.*`). Same ingress as channels.*
      //    (broker session verified above); gates + serialize + audit + vault docs are injected as
      //    closures so the op family shares this DO's exact mechanisms (one mechanism, ADR-0013). ──
      //    The coordination scopes are ADDITIVE (the org.applications precedent, see REQUIRED_SCOPES
      //    note): a grant signed before the coordination wave is denied per-record at demo-mcp
      //    (`record_scope_denied`) — surfaced here as an explicit 409 re-enable signal, never a 500 and
      //    never a weaker read path.
      if (op.startsWith('endeavor.')) {
        // Spec 408 §2.1 / org-leaf-decay (2026-10-03) — PRE-FLIGHT THE SIGNING LEAF. The org's 1-year
        // interactions grant can be perfectly current while the DEL-001 session leaf that fuels the read
        // is expired (12 h) or predates the audience requirement. That used to reach demo-mcp, fail with a
        // bare "auth failed — mcp: auth failed", and 409-storm the Work page with no actionable signal —
        // the self-heal never fired (status said current) and the UI showed no re-enable. Say it plainly
        // here, BEFORE the read, with the same `needsReEnable` shape the coordination-scope path uses, so
        // the Home surfaces the re-enable ceremony (a steward renews the leaf) instead of a dead loop.
        const stLeaf = ((await this.state.storage.get('state')) ?? {}) as StoredState;
        if (await this.sessionLeafStale(stLeaf)) {
          return json({ ok: false, error: 'the agent’s signing session has expired — a steward must re-enable storage to renew it (the organization’s authority is unchanged; only the short-lived session leaf lapsed)', needsReEnable: true }, 409);
        }
        try {
          const res = await handleEndeavorOp({
          principal,
          // Spec 375 — the events a commit appends fire the participants' triggers, off the mutex.
          onCommitted: (endeavorId, events, state) => { this.state.waitUntil(afterEndeavorCommit(this.env, principal as Address, endeavorId, events as never, state).catch(() => undefined)); },
          principalCaip: caip10(Number(this.env.CHAIN_ID ?? 84532), principal as Address),
          sessionSa,
          sessionCaip,
          readDoc: <T,>(resource: string, empty: T): Promise<T> => this.readDoc<T>(grant, resource, empty),
          writeDoc: (resource: string, data: unknown): Promise<void> => this.writeDoc(grant, resource, data),
          serialize: <T,>(fn: () => Promise<T>): Promise<T> => this.serialize(fn),
          // Spec 382 — membership at the endeavor door is the SAME presence the channels use: a current listing,
          // an org→member grant, stewardship, or the organization's own membership record (chain-checked).
          memberName: async () => { const p = await this.communityPresence(grant, principal, sessionSa, sessionCaip, body); return p.admitted ? (p.you ?? 'Member') : null; },
          isSteward: () => this.isSteward(principal, sessionSa, body.stewardship as IncomingDelegation | undefined),
          verifySignature: (account, digest, signature) => this.erc1271(account as Address, digest as Hex, signature as Hex),
          writeAudit: (action, subject, timestamp) =>
            audit.write({ id: crypto.randomUUID(), timestamp: timestamp ?? new Date().toISOString(), action, outcome: 'success', actor: { type: 'user', id: sessionSa }, subject }),
          putTopicBody: async (envelope, bodyText) => {
            const store = createVaultMessageBodyStore(this.vaultFor(grant), principal);
            await store.putBody({ messageId: envelope.id, bytes: new TextEncoder().encode(bodyText), contentType: 'text/plain', classification: 'internal', resource: envelope.body.resource });
          },
          draftPlanForGoal: (endeavorId, goal) => this.dispatchEndeavorPlanDraft(principal, endeavorId, goal),
        }, op, body);
          // spec 334 §6 auto-work triggers (best-effort; each dispatcher no-ops unless the switch is on):
          //   · a submitted request → the org agent auto-triages (ADOPT), which seeds the plan draft
          //     → which (auto-work) chains into execute → satisfy.
          //   · a human-adopted plan → the agent executes the steps it can and satisfies the endeavor.
          if (res.ok) {
            if (op === 'endeavor.request') {
              const rid = ((await res.clone().json().catch(() => ({}))) as { requestId?: string }).requestId;
              if (rid) this.dispatchEndeavorAutoAdopt(principal, rid);
            } else if (op === 'endeavor.adoptPlan') {
              const eid = String(body.endeavorId ?? '');
              if (eid.startsWith('end_')) this.dispatchEndeavorWork(principal, eid);
            }
          }
          return res;
        } catch (e) {
          // The ONLY mapped failure: the interactions grant predates the coordination scopes
          // (demo-mcp per-record `record_scope_denied`) ⇒ the steward re-signs via the Enable ceremony.
          // Anything else rethrows — no blanket catch downgrading real faults.
          const msg = e instanceof Error ? e.message : String(e);
          if (/record_scope_denied/.test(msg)) {
            return json({ ok: false, error: 'interactions grant is stale for coordination — a steward must re-enable discussion storage to add the vault:coordination.* scopes', needsReEnable: true }, 409);
          }
          throw e;
        }
      }

      // ── spec 327 §4b — the org's assistant PLAYBOOK (Agent Skill package / SKILL.md projection):
      //    steward-authored markdown that becomes the LLM planner's system prompt. Org-level (one doc,
      //    all topics); the must-post contract stays STRUCTURAL (single tool) regardless of its text. ──
      if (op === 'channels.assistantSkill.get' || op === 'channels.assistantSkill.put') {
        const steward = await this.isSteward(principal, sessionSa, body.stewardship as IncomingDelegation | undefined);
        // A MEMBER MAY READ the playbook that answers them (owner, 2026-10-05); only a steward writes it. Membership is
        // the same admission the boards use (a governed workspace's members through its governor). Reading it grants nothing.
        if (!steward && !(op === 'channels.assistantSkill.get' && (await this.communityPresence(grant, principal, sessionSa, sessionCaip, body)).admitted)) {
          return json({ error: op === 'channels.assistantSkill.get' ? 'only a member or steward of this organization may read its assistant playbook' : 'only the organization custodian may author the assistant playbook' }, 403);
        }
        if (op === 'channels.assistantSkill.get') {
          const doc = await this.readDoc<AssistantSkillDocV1 | null>(grant, ASSISTANT_SKILL_RESOURCE, null);
          return json({ ok: true, skill: doc });
        }
        const markdown = String(body.markdown ?? '');
        if (markdown.length > ASSISTANT_SKILL_MAX_CHARS) return json({ error: `playbook too long (max ${ASSISTANT_SKILL_MAX_CHARS} chars)` }, 400);
        const doc: AssistantSkillDocV1 = { version: 'ap.assistant-skill.v1', markdown, updatedBy: sessionSa.toLowerCase(), updatedAt: new Date().toISOString() };
        await audit.write({ id: crypto.randomUUID(), timestamp: doc.updatedAt, action: 'interactions.channels.assistantSkillPut', outcome: 'success', actor: { type: 'user', id: sessionSa }, subject: { type: 'assistant-skill', id: principal } });
        await this.writeDoc(grant, ASSISTANT_SKILL_RESOURCE, doc);

        // spec 334 §6 — the KNOWLEDGE BASE the playbook names, written in the SAME custodian act.
        // The gather sub-turn reads these back through internal.coordination.vaultRead; until now
        // nothing ever wrote them, so that read always came back empty and callers compensated by
        // embedding data as prose in the playbook. Prose is not a knowledge base: it cannot be
        // queried, it inflates every turn, and it goes stale silently.
        //
        // Same grant, same steward gate as the playbook — no new authority. Record scope is still
        // enforced downstream by demo-mcp, so an out-of-scope type is DENIED there rather than
        // trusted here.
        const seeded: string[] = [];
        const rejected: string[] = [];
        const records = body.records && typeof body.records === 'object' ? body.records as Record<string, unknown> : null;
        if (records) {
          for (const [recordType, data] of Object.entries(records)) {
            // A domain record must never be able to address a CONTROL document. The topic index, the
            // playbook itself and the directory all live under these prefixes; without this guard a
            // record type of "conversation.topic:assistant-skill" would overwrite the playbook that
            // just authorized the write.
            const reserved = /^(conversation\.|directory\.|dm\.|inbox\.|content\.|invite\.|applications\.)/i.test(recordType);
            const wellFormed = /^[a-z][a-z0-9_.:-]{0,63}$/i.test(recordType);
            if (reserved || !wellFormed || data === undefined) { rejected.push(recordType); continue; }
            try { await this.writeDoc(grant, recordType, data); seeded.push(recordType); }
            catch { rejected.push(recordType); }
          }
        }
        // Report both. A silently-dropped record type is a knowledge base the operator believes is
        // loaded and the agent cannot see.
        return json({ ok: true, ...(records ? { seeded, rejected } : {}) });
      }

      // ── spec 354 K3 — the AGENT's ARCHETYPE ASSIGNMENT (Behaviour → Archetype). The steward-gated
      //    twin of the person's self-written `archetype.assignment` record: an org / workspace / treasury
      //    agent's playbook is authored by its CUSTODIAN, not by the agent's own session. Same steward
      //    gate + same org grant as the assistant playbook above — writing it GRANTS NO AUTHORITY
      //    (ADR-0041 / spec 354 §1): it changes what the agent knows how to do; the mandate still decides
      //    what it may do. The a2a harness re-derives the digest from the embedded definition at run
      //    admission (`src/playbook.ts`); a tampered or absent record leaves the bare harness. ──
      if (op === 'channels.archetypeAssignment.get' || op === 'channels.archetypeAssignment.put') {
        // SELF **OR** STEWARD. An org/workspace/treasury agent's playbook is authored by its custodian
        // through a stewardship wire — but a PERSON is the custodian of their own agent, and there is no
        // wire from someone to themselves. Gating on stewardship alone locked every person out of their
        // own Behaviour panel: the read came back 403 and the ceremony could neither show nor clear an
        // assignment. Both are custody; only the shape of the proof differs.
        const isSelf = sessionSa.toLowerCase() === principal;
        const steward = isSelf || await this.isSteward(principal, sessionSa, body.stewardship as IncomingDelegation | undefined);
        // A MEMBER MAY READ the playbook that answers them (owner, 2026-10-05) — reading is not assigning; only the
        // custodian (self or steward) writes it. Membership is the boards' admission (a workspace's via its governor).
        if (!steward && !(op === 'channels.archetypeAssignment.get' && (await this.communityPresence(grant, principal, sessionSa, sessionCaip, body)).admitted)) {
          return json({ error: op === 'channels.archetypeAssignment.get' ? 'only a member or the custodian of this agent may read its playbook' : 'only the agent’s custodian may assign an archetype' }, 403);
        }
        if (op === 'channels.archetypeAssignment.get') {
          const doc = await this.readDoc<unknown>(grant, 'archetype.assignment', null);
          return json({ ok: true, record: doc });
        }
        if (body.record === undefined) return json({ error: 'record required (null clears the assignment)' }, 400);
        // `null` REMOVES the playbook — the agent goes back to the bare harness, which is a real choice a
        // steward makes and not a broken state. `loadPlaybook` reads a non-object as absent, so this is
        // the same outcome as never having assigned one.
        await audit.write({ id: crypto.randomUUID(), timestamp: new Date().toISOString(), action: body.record === null ? 'interactions.channels.archetypeAssignmentClear' : 'interactions.channels.archetypeAssignmentPut', outcome: 'success', actor: { type: 'user', id: sessionSa }, subject: { type: 'archetype-assignment', id: principal } });
        await this.writeDoc(grant, 'archetype.assignment', body.record);
        return json({ ok: true, cleared: body.record === null });
      }

      // ── spec 400 W1c — WHERE THE MEMBER'S RUNTIME LIVES, and what its wakes came to. The custodian's
      //    declaration (self or steward, the archetype-assignment gate): a Container instance the app binds, or a
      //    URL that serves `POST /wake`. DO-local: it is config for the serving plane (wiped ⇒ re-declared with
      //    `ap runtime host`), not a record — and it authorizes nothing; the runtime's acts are judged by its wire
      //    and its grant when they arrive. `runtime.wake.get` reads the bounded ledger of wake receipts. ──
      // ── Spec 400 W2 (B5) — SEARCH OVER THIS OBJECT'S OWN INDEX (self or steward): messages (a person's), topic posts
      //    (an organization's). `search.reindex` rebuilds it from the records — the index is a projection, and a
      //    rebuild is what "wiped" costs. Results cite ids; the reader opens the record where it lives. ──
      if (op === 'search.query' || op === 'search.reindex') {
        const isSelf = sessionSa.toLowerCase() === principal;
        const steward = isSelf || await this.isSteward(principal, sessionSa, body.stewardship as IncomingDelegation | undefined);
        if (!steward) return json({ error: 'only this agent or its steward may search its records' }, 403);
        if (op === 'search.query') {
          const idx = ((await this.state.storage.get(SEARCH_INDEX_KEY)) as SearchIndexV1 | undefined) ?? emptyIndex();
          const kinds = Array.isArray(body.kinds) ? (body.kinds as string[]).filter((k): k is SearchDocV1['kind'] => k === 'message' || k === 'topic' || k === 'run') : undefined;
          const hits = searchIndex(idx, String(body.query ?? ''), { ...(kinds?.length ? { kinds } : {}), ...(typeof body.since === 'string' ? { since: body.since } : {}), ...(typeof body.limit === 'number' ? { limit: body.limit } : {}) });
          return json({ ok: true, hits, indexed: idx.order.length });
        }
        // REBUILD from the records this object serves: the inbox (bodies batched by resource) and every topic.
        const idx = emptyIndex();
        let n = 0;
        const inbox = await this.readDoc<{ envelopes?: MessageEnvelopeV1[] }>(grant, INBOX_RESOURCE, {}).catch(() => ({} as { envelopes?: MessageEnvelopeV1[] }));
        const envs = (inbox.envelopes ?? []).slice(-2000);
        const bodies = envs.length ? await this.readTopicBodies(grant, envs as never).catch(() => ({} as Record<string, string>)) : {};
        for (const e of envs) {
          const text = bodies[e.id]; if (!text) continue;
          const from = (String(e.from).match(/0x[0-9a-fA-F]{40}$/)?.[0] ?? '').toLowerCase();
          indexDoc(idx, e.id, { kind: 'message', at: e.createdAt, snippet: '', ref: { conversationId: e.conversationId, messageId: e.id, from, ...(e.subject ? { title: e.subject } : {}) } }, text); n += 1;
        }
        const index = await this.readDoc<ChannelV1[]>(grant, CONVERSATION_INDEX_RESOURCE, []).catch(() => [] as ChannelV1[]);
        for (const ch of index) {
          const messages = await this.readDoc<{ envelope: MessageEnvelopeV1; authorName?: string }[]>(grant, TOPIC_RESOURCE(ch.descriptor.id), []).catch(() => []);
          const tb = messages.length ? await this.readTopicBodies(grant, messages.map((m) => m.envelope) as never).catch(() => ({} as Record<string, string>)) : {};
          for (const m of messages) {
            const text = tb[m.envelope.id]; if (!text) continue;
            const from = (String(m.envelope.from).match(/0x[0-9a-fA-F]{40}$/)?.[0] ?? '').toLowerCase();
            indexDoc(idx, m.envelope.id, { kind: 'topic', at: m.envelope.createdAt, snippet: '', ref: { org: principal, channelId: ch.descriptor.id, messageId: m.envelope.id, from, ...(m.authorName ? { fromName: m.authorName } : {}), title: ch.title } }, text); n += 1;
          }
        }
        await this.state.storage.put(SEARCH_INDEX_KEY, idx);
        await audit.write({ id: crypto.randomUUID(), timestamp: new Date().toISOString(), action: 'interactions.search.reindex', outcome: 'success', actor: { type: 'user', id: sessionSa }, subject: { type: 'search-index', id: principal }, reason: `${n} document(s)` });
        return json({ ok: true, indexed: n });
      }

      // Spec 400 W2a/B4 — the STANDING GRANT the custodian issued to this agent's runtime key, kept on the agent's
      // object (like a read grant) so the grants screen lists it and revocation can expand it. Verified as issued by
      // this agent (ERC-1271 over its digest) before it is kept; a steward's act.
      if (op === 'runtime.standing.put' || op === 'runtime.standing.list') {
        const isSelf = sessionSa.toLowerCase() === principal;
        const steward = isSelf || await this.isSteward(principal, sessionSa, body.stewardship as IncomingDelegation | undefined);
        if (!steward) return json({ error: 'only the agent’s custodian may record a standing grant' }, 403);
        if (op === 'runtime.standing.list') {
          const out: Array<Omit<StandingGrantRecord, 'wire'>> = [];
          for (const [, v] of await this.state.storage.list({ prefix: STANDING_GRANT_KEY('') })) { const { wire: _w, ...rest } = v as StandingGrantRecord; out.push(rest); }
          return json({ ok: true, grants: out });
        }
        const wire = body.wire as IncomingDelegation | undefined;
        if (!wire || wire.delegator.toLowerCase() !== principal) return json({ error: 'a standing grant is this agent\'s own delegation' }, 400);
        const d: Delegation = { ...wire, salt: BigInt(String(wire.salt)), caveats: wire.caveats.map((c) => ({ enforcer: c.enforcer, terms: c.terms, args: (c.args ?? '0x') as Hex })) } as Delegation;
        const hash = hashDelegation(d, Number(this.env.CHAIN_ID ?? 84532), this.env.DELEGATION_MANAGER as Address);
        if (!(await this.erc1271(principal as Address, hash, wire.signature as Hex))) return json({ error: 'the standing grant\'s signature does not verify against this agent' }, 403);
        const rec: StandingGrantRecord = { wire, hash, capabilities: Array.isArray(body.capabilities) ? (body.capabilities as string[]).map(String) : [], locations: Array.isArray(body.locations) ? (body.locations as string[]).map(String) : [], holder: String(wire.delegate).toLowerCase(), ...(typeof body.holderName === 'string' ? { holderName: body.holderName } : {}), validUntil: Number(body.validUntil ?? 0), storedAt: new Date().toISOString() };
        await this.state.storage.put(STANDING_GRANT_KEY(hash), rec);
        await audit.write({ id: crypto.randomUUID(), timestamp: rec.storedAt, action: 'interactions.runtime.standingPut', outcome: 'success', actor: { type: 'user', id: sessionSa }, subject: { type: 'delegation', id: hash } });
        return json({ ok: true, hash });
      }

      // Spec 400 W1b — PAIRING CODES on the custodian's own object: mint (what the runtime will get, chosen here),
      // list (the claims waiting for her approval), complete (the record her browser equipped), cancel.
      if (op === 'runtime.pairing.mint' || op === 'runtime.pairing.list' || op === 'runtime.pairing.complete' || op === 'runtime.pairing.cancel') {
        if (sessionSa.toLowerCase() !== principal) return json({ error: 'pairing codes are minted on your own agent' }, 403);
        const index = ((await this.state.storage.get(PAIRING_INDEX_KEY)) as string[] | undefined) ?? [];
        const now = Date.now();
        // sweep what has expired — a pairing is a moment
        const live: string[] = [];
        for (const c of index) { const st = (await this.state.storage.get(PAIRING_KEY(c))) as PairingStateV1 | undefined; if (!st || pairingExpired(st, now)) await this.state.storage.delete(PAIRING_KEY(c)); else live.push(c); }
        if (op === 'runtime.pairing.mint') {
          const options = parsePairingOptions(body.options);
          if (!options) return json({ error: 'options: { member: <label>.svc, workspace: <label>.org, validForSeconds?, openMandate?: [], messagingTo?: [], wake?: container | poll | { url } }' }, 400);
          const handle = String(body.handle ?? '').trim() || principal.slice(2, 8);
          let code = mintCode(handle);
          for (let i = 0; i < 5 && live.includes(code); i++) code = mintCode(handle);
          const st: PairingStateV1 = { v: 1, code, state: 'minted', options, mintedAt: new Date(now).toISOString(), expiresAt: new Date(now + PAIRING_TTL_MS).toISOString() };
          const next = [...live, code]; const evict = next.length > PAIRING_CAP ? next.splice(0, next.length - PAIRING_CAP) : [];
          for (const e of evict) await this.state.storage.delete(PAIRING_KEY(e));
          await this.state.storage.put(PAIRING_KEY(code), st); await this.state.storage.put(PAIRING_INDEX_KEY, next);
          await audit.write({ id: crypto.randomUUID(), timestamp: st.mintedAt, action: 'interactions.runtime.pairingMint', outcome: 'success', actor: { type: 'user', id: sessionSa }, subject: { type: 'runtime-pairing', id: code }, reason: `${options.member} in ${options.workspace}` });
          return json({ ok: true, pairing: st });
        }
        if (op === 'runtime.pairing.list') {
          const out: PairingStateV1[] = [];
          for (const c of live) { const st = (await this.state.storage.get(PAIRING_KEY(c))) as PairingStateV1 | undefined; if (st) { const { record: _r, ...rest } = st as PairingStateV1 & { record?: unknown }; out.push(rest as PairingStateV1); } }
          await this.state.storage.put(PAIRING_INDEX_KEY, live);
          return json({ ok: true, pairings: out });
        }
        const code = String(body.code ?? '').trim();
        const cur = (await this.state.storage.get(PAIRING_KEY(code))) as PairingStateV1 | undefined;
        if (!cur || !live.includes(code)) return json({ error: 'unknown or expired code' }, 404);
        if (op === 'runtime.pairing.cancel') {
          await this.state.storage.delete(PAIRING_KEY(code)); await this.state.storage.put(PAIRING_INDEX_KEY, live.filter((c) => c !== code));
          await audit.write({ id: crypto.randomUUID(), timestamp: new Date().toISOString(), action: 'interactions.runtime.pairingCancel', outcome: 'success', actor: { type: 'user', id: sessionSa }, subject: { type: 'runtime-pairing', id: code } });
          return json({ ok: true });
        }
        const r = pairingComplete(cur, body.record, now);
        if (!r.ok) return json({ error: r.error }, 409);
        await this.state.storage.put(PAIRING_KEY(code), r.next); await this.state.storage.put(PAIRING_INDEX_KEY, live);
        await audit.write({ id: crypto.randomUUID(), timestamp: new Date().toISOString(), action: 'interactions.runtime.pairingComplete', outcome: 'success', actor: { type: 'user', id: sessionSa }, subject: { type: 'runtime-pairing', id: code }, reason: cur.options.member });
        return json({ ok: true });
      }

      if (op === 'runtime.host.get' || op === 'runtime.host.put' || op === 'runtime.wake.get') {
        const isSelf = sessionSa.toLowerCase() === principal;
        const steward = isSelf || await this.isSteward(principal, sessionSa, body.stewardship as IncomingDelegation | undefined);
        if (!steward) return json({ error: 'only the agent’s custodian may say where its runtime lives' }, 403);
        if (op === 'runtime.host.get') return json({ ok: true, host: parseRuntimeHost(await this.state.storage.get(RUNTIME_HOST_KEY)) });
        if (op === 'runtime.host.put') {
          if (body.host === null) { await this.state.storage.delete(RUNTIME_HOST_KEY); return json({ ok: true, host: null }); }
          const host = parseRuntimeHost(body.host);
          if (!host) return json({ error: 'host must be { v: 1, kind: "container" } or { v: 1, kind: "url", url } (null clears it)' }, 400);
          await this.state.storage.put(RUNTIME_HOST_KEY, host);
          await audit.write({ id: crypto.randomUUID(), timestamp: new Date().toISOString(), action: 'interactions.runtime.hostPut', outcome: 'success', actor: { type: 'user', id: sessionSa }, subject: { type: 'runtime-host', id: principal }, reason: host.kind });
          return json({ ok: true, host });
        }
        const ids = ((await this.state.storage.get(RUNTIME_WAKES_KEY)) as string[] | undefined) ?? [];
        const want = typeof body.messageId === 'string' ? [body.messageId] : ids.slice(-Number(body.limit ?? 10));
        const wakes = (await Promise.all(want.map((id) => this.state.storage.get(`${RUNTIME_WAKE_PREFIX}${id}`)))).filter(Boolean) as WakeReceiptV1[];
        return json({ ok: true, wakes });
      }

      // ── spec 327 — the org assistant on a topic (318 §8.1: the org's OWN agent, steward-enabled). ──
      if (op === 'channels.assistantEnable' || op === 'channels.assistantDisable') {
        const steward = await this.isSteward(principal, sessionSa, body.stewardship as IncomingDelegation | undefined);
        if (!steward) return json({ error: 'only the organization custodian may manage the topic assistant' }, 403);
        const channelId = String(body.channelId ?? '');
        if (!channelId) return json({ error: 'channelId required' }, 400);
        if (op === 'channels.assistantDisable') {
          return this.serialize(async () => { // conversation.index RMW — same single-writer rule as create
            const index = await this.readDoc<ChannelV1[]>(grant, CONVERSATION_INDEX_RESOURCE, []);
            const r = setTopicAssistant(index, channelId, undefined);
            if (!r.ok) return json({ error: r.error }, 404);
            await audit.write({ id: crypto.randomUUID(), timestamp: new Date().toISOString(), action: 'interactions.channels.assistantDisable', outcome: 'success', actor: { type: 'user', id: sessionSa }, subject: { type: 'channel', id: channelId } });
            await this.writeDoc(grant, CONVERSATION_INDEX_RESOURCE, index);
            return json({ ok: true });
          });
        }
        const trigger: TopicAssistantV1['trigger'] = body.trigger === 'all' ? 'all' : 'mention';
        // Capture the org's primary name ONCE at enable time (ADR-0012: one reverseResolveString view
        // call; re-enabling refreshes after a name rotation). A resolver failure fails the ceremony
        // closed — it never silently enables a nameless assistant (ADR-0013).
        let primaryName: string | null = null;
        if (this.env.RPC_URL && this.env.AGENT_NAME_REGISTRY && this.env.AGENT_NAME_UNIVERSAL_RESOLVER) {
          try {
            primaryName = await new AgentNamingClient({
              rpcUrl: this.env.RPC_URL,
              chainId: Number(this.env.CHAIN_ID ?? 84532),
              registry: this.env.AGENT_NAME_REGISTRY as Address,
              universalResolver: this.env.AGENT_NAME_UNIVERSAL_RESOLVER as Address,
            }).reverseResolve(principal as Address);
          } catch (e) {
            return json({ error: `could not resolve the organization's primary name: ${e instanceof Error ? e.message : String(e)}` }, 502);
          }
        }
        const mentionHandle = primaryName ? (primaryName.split('.')[0] ?? '').toLowerCase() : '';
        const displayName = primaryName ?? String(body.displayName ?? '').trim();
        if (trigger === 'mention' && !mentionHandle) return json({ error: 'this organization has no primary name to mention — set one first, or enable the assistant with trigger "all"' }, 409);
        if (!displayName) return json({ error: 'displayName required when the organization has no primary name' }, 400);
        return this.serialize(async () => {
          const index = await this.readDoc<ChannelV1[]>(grant, CONVERSATION_INDEX_RESOURCE, []);
          const r = setTopicAssistant(index, channelId, { trigger, mentionHandle, displayName, enabledBy: sessionSa.toLowerCase(), enabledAt: new Date().toISOString() });
          if (!r.ok) return json({ error: r.error }, r.error === 'unknown channel' ? 404 : 400);
          await audit.write({ id: crypto.randomUUID(), timestamp: new Date().toISOString(), action: 'interactions.channels.assistantEnable', outcome: 'success', actor: { type: 'user', id: sessionSa }, subject: { type: 'channel', id: channelId } });
          await this.writeDoc(grant, CONVERSATION_INDEX_RESOURCE, index);
          return json({ ok: true, assistant: r.channel.assistant });
        });
      }

      // ── spec 329 §3.1/§7 — steward member-routing ceremony + per-topic toggle. The ENABLE mints
      //    (first time) the DO-held ORG consult wire: org → the interactions-session KMS key,
      //    consult-selector-only, steward-signed with the org's custody credential — the runtime's
      //    authority to SIGN consult-rail messages as the org (no raw key at rest). Disable clears
      //    the topic flag immediately (and optionally the wire) + cancels pending consults. ──
      if (op === 'consult.routingEnable' || op === 'consult.routingDisable' || op === 'consult.routingStatus') {
        const steward = await this.isSteward(principal, sessionSa, body.stewardship as IncomingDelegation | undefined);
        if (!steward) return json({ error: 'only the organization custodian may manage member routing' }, 403);
        if (op === 'consult.routingStatus') {
          const wireRec = (await this.state.storage.get(ROUTING_ORG_WIRE_KEY)) as RoutingOrgWireRecord | undefined;
          // The session-key address the CLIENT needs to mint the wire (the NEW-C1 key, §3.1 pairing).
          let sessionKey: string | null = null;
          try { sessionKey = (await interactionsSessionAccount(this.env)).address; } catch { /* unprovisioned ⇒ null */ }
          return json({ ok: true, wirePresent: !!wireRec, enabledAt: wireRec?.enabledAt ?? null, sessionKey });
        }
        const channelId = String(body.channelId ?? '');
        if (!channelId) return json({ error: 'channelId required' }, 400);
        if (op === 'consult.routingDisable') {
          return this.serialize(async () => {
            const index = await this.readDoc<ChannelV1[]>(grant, CONVERSATION_INDEX_RESOURCE, []);
            const r = setTopicRouting(index, channelId, undefined);
            if (!r.ok) return json({ error: r.error }, 404);
            await this.writeDoc(grant, CONVERSATION_INDEX_RESOURCE, index);
            if (body.clearWire === true) await this.state.storage.delete(ROUTING_ORG_WIRE_KEY);
            // Steward disable = immediate: pending consults for this topic are cancelled at the
            // org's task runtime (in-Worker, marker-gated). Best-effort — the turn-2 poller also
            // re-checks the wire/flag and drops on absence (belt to this suspender).
            try {
              const stub = this.env.A2A_TASKS.get(this.env.A2A_TASKS.idFromName(principal));
              await stub.fetch(new Request(`https://do/internal/routing-cancel?agent=${principal}`, {
                method: 'POST', headers: internalHeaders(this.env),
                body: JSON.stringify({ channelId }),
              }));
            } catch { /* audited by the poller's own drop path */ }
            await audit.write({ id: crypto.randomUUID(), timestamp: new Date().toISOString(), action: 'interactions.routing.disable', outcome: 'success', actor: { type: 'user', id: sessionSa }, subject: { type: 'channel', id: channelId } });
            return json({ ok: true });
          });
        }
        // consult.routingEnable — verify + custody the wire (when supplied / first enable), then flag the topic.
        const wireRec = (await this.state.storage.get(ROUTING_ORG_WIRE_KEY)) as RoutingOrgWireRecord | undefined;
        const incoming = body.delegation as IncomingDelegation | undefined;
        if (!wireRec && !incoming) return json({ error: 'org consult wire required — the routing ceremony signs it first' }, 400);
        if (incoming) {
          if (incoming.delegator.toLowerCase() !== principal) return json({ error: 'org consult wire delegator must be this organization' }, 400);
          // Delegate MUST be the interactions-session KMS key (the §3.1 pairing) — fail-closed if unprovisioned.
          let sessionKey: string;
          try { sessionKey = (await interactionsSessionAccount(this.env)).address.toLowerCase(); } catch {
            return json({ error: 'interactions-session key unprovisioned — routing needs AKCS_INTERACTIONS_KEY_ID (agentic-kms) or GCP_KMS_INTERACTIONS_KEY_NAME (gcp-kms)' }, 503);
          }
          if (incoming.delegate.toLowerCase() !== sessionKey) return json({ error: 'org consult wire delegate must be the interactions-session key' }, 400);
          const tsEnf = (this.env.TIMESTAMP_ENFORCER ?? '').toLowerCase();
          const amEnf = (this.env.ALLOWED_METHODS_ENFORCER ?? '').toLowerCase();
          if (![tsEnf, amEnf].every((a) => /^0x[0-9a-f]{40}$/.test(a))) return json({ error: 'consult enforcers not configured — cannot verify the wire shape' }, 503);
          // Ceremony store time for the CONSULT rail specifically — pin the consult selector, the
          // behaviour this check always had. The shape function is now skill-agnostic, so the pin
          // has to be stated rather than assumed.
          const shapeErr = checkSessionWireShape(incoming, { timestamp: tsEnf, allowedMethods: amEnf }, Math.floor(Date.now() / 1000), { skill: CONSULT_SKILL_ID });
          if (shapeErr) return json({ error: shapeErr }, 400);
          const d: Delegation = { ...incoming, salt: BigInt(incoming.salt), caveats: incoming.caveats.map((c) => ({ enforcer: c.enforcer, terms: c.terms, args: (c.args ?? '0x') as Hex })) } as Delegation;
          const digest = hashDelegation(d, Number(this.env.CHAIN_ID ?? 84532), this.env.DELEGATION_MANAGER as Address);
          if (!(await this.erc1271(incoming.delegator as Address, digest, incoming.signature as Hex))) {
            return json({ error: 'org consult wire signature failed verification against the organization' }, 403);
          }
          try {
            const revoked = (await this.pub().readContract({ address: this.env.DELEGATION_MANAGER as Address, abi: IS_REVOKED_ABI, functionName: 'isRevoked', args: [digest] })) as boolean;
            if (revoked) return json({ error: 'org consult wire is already revoked on-chain' }, 403);
          } catch { return json({ error: 'revocation check unavailable — wire not stored (fail-closed)' }, 503); }
          const rec: RoutingOrgWireRecord = { wire: incoming, hash: digest, sessionKey, enabledBy: sessionSa.toLowerCase(), enabledAt: new Date().toISOString() };
          await this.state.storage.put(ROUTING_ORG_WIRE_KEY, rec);
          st.ledger = [...(st.ledger ?? []), { hash: digest, delegate: sessionKey, resources: ['(routing:consult-sign)'], storedAt: rec.enabledAt }].slice(-50);
          await this.state.storage.put('state', st);
        }
        const rawFanout = Number(body.maxFanout ?? ROUTING_FANOUT_DEFAULT);
        return this.serialize(async () => {
          const index = await this.readDoc<ChannelV1[]>(grant, CONVERSATION_INDEX_RESOURCE, []);
          const r = setTopicRouting(index, channelId, { maxFanout: rawFanout, enabledBy: sessionSa.toLowerCase(), enabledAt: new Date().toISOString() });
          if (!r.ok) return json({ error: r.error }, r.error === 'unknown channel' ? 404 : 409);
          await this.writeDoc(grant, CONVERSATION_INDEX_RESOURCE, index);
          await audit.write({ id: crypto.randomUUID(), timestamp: new Date().toISOString(), action: 'interactions.routing.enable', outcome: 'success', actor: { type: 'user', id: sessionSa }, subject: { type: 'channel', id: channelId } });
          return json({ ok: true, routing: r.channel.routing });
        });
      }

      // ── spec 341 §5.6 — `content.shared`. The OWNER releases one artifact, or nothing. ──
      //
      // Same inversion as `applications.mine`, applied to the library's cross-vault read. The caller
      // used to pull the owner's ENTIRE catalog and then evaluate the sharing grants at the Home — so
      // every artifact the owner had crossed the wire to answer a question about one, and the check
      // that mattered ran after the disclosure it was meant to prevent.
      //
      // Now the owner's own agent evaluates its own grants and returns the ONE artifact, or nothing.
      // The catalog never leaves. The reader learns of no artifact it was not granted — not even that
      // one exists.
      if (op === 'content.shared') {
        const artifactId = String(body.artifactId ?? '');
        if (!artifactId) return json({ error: 'artifactId required' }, 400);
        const list = ((await this.vaultFor(grant).read<unknown>({ owner: '', resource: 'content.catalog' }))?.data ?? []) as Array<Record<string, unknown>>;
        const art = Array.isArray(list) ? list.find((x) => String(x?.id ?? '') === artifactId) : undefined;
        const reader = sessionSa.toLowerCase();
        // ABSENT and NOT-SHARED answer identically. Distinguishing them would let a reader enumerate
        // what an owner holds by asking for ids and reading the difference in the refusal.
        if (!art) return json({ ok: true, artifact: null });
        const grantsOf = (a: Record<string, unknown>): Array<{ grantee?: { address?: string }; revoked?: boolean }> =>
          (Array.isArray(a.grants) ? a.grants : []) as Array<{ grantee?: { address?: string }; revoked?: boolean }>;
        // Own grants plus those inherited from any ancestor folder — the containment cascade, evaluated
        // HERE against the authoritative list rather than against a copy the caller was handed.
        const chain: Array<Record<string, unknown>> = [art];
        let cursor = art;
        for (let i = 0; i < 16 && cursor?.folder; i++) {
          const parent = list.find((x) => String(x?.id ?? '') === String(cursor.folder));
          if (!parent) break;
          chain.push(parent);
          cursor = parent;
        }
        const shared = chain.some((a) => grantsOf(a).some((gr) => !gr.revoked && String(gr.grantee?.address ?? '').toLowerCase() === reader));
        if (!shared) return json({ ok: true, artifact: null });
        return json({ ok: true, artifact: art });
      }

      // ── spec 341 §5.6 — `applications.mine`. THE HOLDER DECIDES WHAT TO SHOW. ──
      //
      // The shape this replaces appeared twice: a caller with no authority over a collection read the
      // WHOLE collection and filtered afterwards. An org's steward pulled an alliance's entire pending
      // list to find their own row; the library pulled another org's full catalog to find what was
      // shared. In both, the decision about what the caller may see happened at the HOME, after an
      // unauthorized read — so a filter bug is a DISCLOSURE, not a denial.
      //
      // Inverting it costs nothing and fixes the class: this agent holds the collection, so this agent
      // filters, and the rest never leaves. The caller is told what is theirs, and cannot be told
      // anything else by getting the filter wrong.
      if (op === 'applications.mine') {
        // Rows belonging to the CALLER — either they applied, or they applied FOR an org they steward.
        // Stewardship is proven, not asserted: an unproven org claim is simply dropped from the set
        // rather than refused, because a caller may legitimately hold rows for some orgs and not others.
        const subjects = new Set<string>([sessionSa.toLowerCase()]);
        const claimed = Array.isArray(body.subjects) ? (body.subjects as unknown[]).map((x) => String(x).toLowerCase()) : [];
        for (const sub of claimed.slice(0, 32)) {
          if (!/^0x[0-9a-f]{40}$/.test(sub)) continue;
          if (await this.isSteward(sub, sessionSa, body.stewardship as IncomingDelegation | undefined)) subjects.add(sub);
        }
        const doc = await this.readDoc<{ applications?: unknown[] }>(grant, APPLICATIONS_RESOURCE, { applications: [] });
        const rows = Array.isArray(doc?.applications) ? doc.applications : [];
        const mine = rows.filter((r) => {
          const row = r as { applicant?: string; subject?: string };
          const applicant = String(row.applicant ?? '').toLowerCase();
          const subject = String(row.subject ?? '').toLowerCase();
          return subjects.has(applicant) || (subject !== '' && subjects.has(subject));
        });
        return json({ ok: true, applications: mine });
      }

      // ── spec 341 §5.5b — INVITE CLAIM. Not admission: the org ALREADY acted, and the record it
      //    minted is addressed to this caller. They are collecting, not requesting. ──
      if (op === 'invite.claim') {
        // THE KEY IS DERIVED FROM THE SESSION, NEVER SUPPLIED. `invite.get` took a `{ resource }` and
        // the caller said which record — so "read an invite" and "read ANY invite" were the same op,
        // separated only by the caller's manners. Deriving it makes the op mean "read the invite
        // addressed to me", which is the entire security property and the one a caller-supplied key
        // gives away silently.
        const mine = `org.invite:agent:${sessionSa.toLowerCase()}`;
        // Read under the ORG's own grant: the invitee holds nothing here — not having authority yet is
        // precisely the situation an invite exists to change (§5.5).
        const rec = await this.vaultFor(grant).read<unknown>({ owner: '', resource: mine });
        const data = (rec?.data ?? null) as { status?: string } | null;
        // A REVOKED or already-used invite is not an invite. Returning it and letting the caller check
        // would make the status advisory; refusing here makes it a gate.
        if (data && data.status && data.status !== 'pending') {
          return json({ ok: true, invite: null, reason: data.status });
        }
        return json({ ok: true, invite: data });
      }

      // ── STUDY GRANTS — the person authorizes ONE COACH SERVICE to read their card-room study records
      //    (`cardroom.hand|style|read|note`) and to append its notes. Self-access only. The delegate is
      //    the SERVICE (a `.svc` name), never the coach as a person and never this Home's own service SA:
      //    a coach who is fired is fired by revoking exactly this, and nothing of the person's is left on
      //    the service (`card-room.ts`). ──
      if (op === 'studygrant.put' || op === 'studygrant.list' || op === 'studygrant.revoke') {
        if (sessionSa.toLowerCase() !== principal) return json({ error: 'only this agent may decide who studies its play' }, 403);
        if (op === 'studygrant.list') {
          const rows = await this.state.storage.list({ prefix: STUDY_GRANT_KEY('') });
          const grants: Array<{ coach: string; delegate: string; hash: string; resources: string[]; storedAt: string; revoked: boolean }> = [];
          for (const [, v] of rows) {
            const rec = v as StudyGrantRecord;
            let revoked = false;
            try {
              revoked = (await this.pub().readContract({ address: this.env.DELEGATION_MANAGER as Address, abi: IS_REVOKED_ABI, functionName: 'isRevoked', args: [rec.hash as Hex] })) as boolean;
            } catch { revoked = true; }
            grants.push({ coach: rec.coach, delegate: rec.delegate, hash: rec.hash, resources: rec.resources, storedAt: rec.storedAt, revoked });
          }
          return json({ ok: true, grants });
        }
        const coach = String(body.coach ?? '').trim().toLowerCase();
        if (!coach) return json({ error: 'coach required — the service’s typed name' }, 400);
        if (op === 'studygrant.revoke') {
          await this.state.storage.delete(STUDY_GRANT_KEY(coach));
          await audit.write({ id: crypto.randomUUID(), timestamp: new Date().toISOString(), action: 'interactions.studygrant.revoke', outcome: 'success', actor: { type: 'user', id: sessionSa }, subject: { type: 'agent', id: coach } });
          return json({ ok: true, note: 'local copy dropped — revoke the delegation on-chain to kill it everywhere' });
        }
        // studygrant.put
        if (!/\.svc$/.test(coach)) return json({ error: 'a study grant is given to a coaching SERVICE (a .svc name), never to a person' }, 400);
        const incoming = body.delegation as IncomingDelegation | undefined;
        if (!incoming) return json({ error: 'a person-signed study grant is required' }, 400);
        if (incoming.delegator.toLowerCase() !== principal) return json({ error: 'the study grant must be issued BY this agent' }, 400);
        const delegate = String(incoming.delegate ?? '').toLowerCase();
        if (!/^0x[0-9a-f]{40}$/.test(delegate)) return json({ error: 'the study grant must name the service’s address as delegate' }, 400);
        if (delegate === (this.env.INTERACTIONS_SERVICE_SA ?? '').toLowerCase()) return json({ error: 'a study grant delegates to the coach service, not to this Home’s own service' }, 400);
        // The delegate IS the named service: resolved here, so the grant and the name cannot disagree.
        if (this.env.RPC_URL && this.env.AGENT_NAME_REGISTRY && this.env.AGENT_NAME_UNIVERSAL_RESOLVER) {
          const naming = new AgentNamingClient({ rpcUrl: this.env.RPC_URL, chainId: Number(this.env.CHAIN_ID ?? 84532), registry: this.env.AGENT_NAME_REGISTRY as Address, universalResolver: this.env.AGENT_NAME_UNIVERSAL_RESOLVER as Address });
          const resolved = await naming.resolveName(coach).catch(() => null);
          if (!resolved) return json({ error: `"${coach}" does not resolve to an agent` }, 400);
          if (resolved.toLowerCase() !== delegate) return json({ error: `"${coach}" is ${resolved}, not the grant’s delegate` }, 400);
        }
        const scopeCav = (incoming.caveats ?? []).find((c) => (c.enforcer ?? '').toLowerCase() === VAULT_RECORD_SCOPE_ENFORCER.toLowerCase());
        if (!scopeCav?.terms) return json({ error: 'the study grant must carry a vault-record-scope caveat' }, 400);
        let scopes: VaultRecordScopeGrant[] = [];
        try { scopes = decodeVaultRecordScopeTerms(scopeCav.terms as Hex); } catch { return json({ error: 'the study grant’s scope terms are undecodable' }, 400); }
        const resources = scopes.flatMap((gr) => gr.resources);
        if (resources.length === 0) return json({ error: 'the study grant must name at least one resource' }, 400);
        // The four records by name, and the day records by prefix (`vault:cardroom.hands:*`) — never `vault:cardroom.*`
        // whole, which would also cover a coach's own client pointers if it ever kept them here. ONE CABINET PER
        // GAME: hold'em's records are the bare names, every other game's carry the family (`vault:cardroom.canasta.hand`).
        const STUDY_RESOURCE = /^vault:cardroom\.(?:[a-z0-9-]+\.)?[a-z]+(:\*)?$/;
        const STUDY_HAND = /^vault:cardroom\.(?:[a-z0-9-]+\.)?hand$/;
        const STUDY_NOTE = /^vault:cardroom\.(?:[a-z0-9-]+\.)?note$/;
        if (resources.some((r) => !STUDY_RESOURCE.test(r))) return json({ error: 'a study grant scopes card-room study records (vault:cardroom.<record>, vault:cardroom.hands:*, or vault:cardroom.<game>.<record>) and nothing else' }, 400);
        if (!scopes.some((gr) => gr.ops.includes('read') && gr.resources.some((r) => STUDY_HAND.test(r)))) return json({ error: 'the study grant must read a hand record (vault:cardroom.hand, or vault:cardroom.<game>.hand)' }, 400);
        if (scopes.some((gr) => (gr.ops.includes('write') || gr.ops.includes('delete')) && gr.resources.some((r) => !STUDY_NOTE.test(r)))) return json({ error: 'a study grant may write nothing but the coach’s notes (vault:cardroom.note, or vault:cardroom.<game>.note)' }, 400);
        const d: Delegation = { ...incoming, salt: BigInt(incoming.salt), caveats: incoming.caveats.map((c) => ({ enforcer: c.enforcer, terms: c.terms, args: (c.args ?? '0x') as Hex })) } as Delegation;
        const digest = hashDelegation(d, Number(this.env.CHAIN_ID ?? 84532), this.env.DELEGATION_MANAGER as Address);
        if (!(await this.erc1271(incoming.delegator as Address, digest, incoming.signature as Hex))) return json({ error: 'study grant signature failed verification against this agent' }, 403);
        try {
          const revoked = (await this.pub().readContract({ address: this.env.DELEGATION_MANAGER as Address, abi: IS_REVOKED_ABI, functionName: 'isRevoked', args: [digest] })) as boolean;
          if (revoked) return json({ error: 'that study grant is already revoked on-chain' }, 403);
        } catch { return json({ error: 'revocation check unavailable — nothing stored (fail-closed)' }, 503); }
        const rec: StudyGrantRecord = { wire: incoming, hash: digest, coach, delegate, resources, storedAt: new Date().toISOString() };
        await this.state.storage.put(STUDY_GRANT_KEY(coach), rec);
        await audit.write({ id: crypto.randomUUID(), timestamp: rec.storedAt, action: 'interactions.studygrant.put', outcome: 'success', actor: { type: 'user', id: sessionSa }, subject: { type: 'agent', id: coach } });
        return json({ ok: true, coach, delegate, hash: digest, resources });
      }

      // ── spec 341 §4.3 — PER-APP READ GRANTS. The person authorizes ONE app to read, and can revoke
      //    that app alone. Self-access only: nobody else decides which apps may read your records. ──
      if (op === 'readgrant.put' || op === 'readgrant.list' || op === 'readgrant.revoke') {
        if (sessionSa.toLowerCase() !== principal) {
          return json({ error: 'only this agent may decide which apps read its records' }, 403);
        }
        const prefix = READ_GRANT_KEY('');

        if (op === 'readgrant.list') {
          const rows = await this.state.storage.list({ prefix });
          const grants: Array<{ clientId: string; hash: string; storedAt: string; revoked: boolean }> = [];
          for (const [, v] of rows) {
            const rec = v as ReadGrantRecord;
            let revoked = false;
            // Report the ON-CHAIN truth, not the stored row: a person auditing their apps needs to see
            // that a revoke landed. An unreadable chain reports `revoked: true` — the conservative
            // answer for a list whose purpose is spotting access you did not intend.
            try {
              revoked = (await this.pub().readContract({ address: this.env.DELEGATION_MANAGER as Address, abi: IS_REVOKED_ABI, functionName: 'isRevoked', args: [rec.hash as Hex] })) as boolean;
            } catch { revoked = true; }
            grants.push({ clientId: rec.clientId, hash: rec.hash, storedAt: rec.storedAt, revoked });
          }
          return json({ ok: true, grants });
        }

        const clientId = String(body.clientId ?? '').trim().toLowerCase();
        if (!clientId) return json({ error: 'clientId required' }, 400);

        if (op === 'readgrant.revoke') {
          // LOCAL removal only, and it says so. The authority kill is the on-chain revoke of the
          // delegation — which stops the app at every gate, not just at this DO. Dropping the row here
          // stops US using it; a caller who does only this has not revoked anything.
          await this.state.storage.delete(READ_GRANT_KEY(clientId));
          await audit.write({ id: crypto.randomUUID(), timestamp: new Date().toISOString(), action: 'interactions.readgrant.revoke', outcome: 'success', actor: { type: 'user', id: sessionSa }, subject: { type: 'app', id: clientId } });
          return json({ ok: true, note: 'local copy dropped — revoke the delegation on-chain to kill it everywhere' });
        }

        // readgrant.put — the person authorizes one app to read.
        const incoming = body.delegation as IncomingDelegation | undefined;
        if (!incoming) return json({ error: 'a person-signed read grant is required' }, 400);
        if (incoming.delegator.toLowerCase() !== principal) {
          return json({ error: 'the read grant must be issued BY this agent' }, 400);
        }
        // The delegate is the interactions service SA — the party that actually performs the vault
        // call. Pinning it stops a grant being installed that routes this person's reads through some
        // other delegate (NEW-H6, same reasoning as the interactions grant).
        const expectedDelegate = (this.env.INTERACTIONS_SERVICE_SA ?? '').toLowerCase();
        if (/^0x[0-9a-f]{40}$/.test(expectedDelegate) && incoming.delegate.toLowerCase() !== expectedDelegate) {
          return json({ error: 'the read grant must delegate to the interactions service SA' }, 400);
        }
        // It must actually CARRY read scope. A grant that names no resources authorizes nothing, and
        // storing it would produce an app that appears authorized and fails at every read.
        const scopeCav = (incoming.caveats ?? []).find((c) => (c.enforcer ?? '').toLowerCase() === VAULT_RECORD_SCOPE_ENFORCER.toLowerCase());
        if (!scopeCav?.terms) return json({ error: 'the read grant must carry a vault-record-scope caveat' }, 400);
        let resources: string[] = [];
        try {
          resources = decodeVaultRecordScopeTerms(scopeCav.terms as Hex).flatMap((gr) => gr.resources);
        } catch { return json({ error: 'the read grant’s scope terms are undecodable' }, 400); }
        if (resources.length === 0) return json({ error: 'the read grant must name at least one resource' }, 400);
        // DECLARATIVE, not inbox-specific. The first version of this required `vault:inbox.data`, which
        // made the machinery inbox-only while wearing a general name — a grant covering only
        // `vault:skills.data` (the capability record behind /skills) could not be issued at all. What
        // the grant carries is what it authorizes; what an OP needs is checked when the op runs.
        const tooBroad = resources.filter((r) => r === 'vault:*' || r === 'vault:');
        if (tooBroad.length > 0) return json({ error: 'a read grant must scope to record families, never the whole vault' }, 400);
        const d: Delegation = { ...incoming, salt: BigInt(incoming.salt), caveats: incoming.caveats.map((c) => ({ enforcer: c.enforcer, terms: c.terms, args: (c.args ?? '0x') as Hex })) } as Delegation;
        const digest = hashDelegation(d, Number(this.env.CHAIN_ID ?? 84532), this.env.DELEGATION_MANAGER as Address);
        if (!(await this.erc1271(incoming.delegator as Address, digest, incoming.signature as Hex))) {
          return json({ error: 'read grant signature failed verification against this agent' }, 403);
        }
        try {
          const revoked = (await this.pub().readContract({ address: this.env.DELEGATION_MANAGER as Address, abi: IS_REVOKED_ABI, functionName: 'isRevoked', args: [digest] })) as boolean;
          if (revoked) return json({ error: 'that read grant is already revoked on-chain' }, 403);
        } catch { return json({ error: 'revocation check unavailable — nothing stored (fail-closed)' }, 503); }
        const rec: ReadGrantRecord = { wire: incoming, hash: digest, clientId, storedAt: new Date().toISOString() };
        await this.state.storage.put(READ_GRANT_KEY(clientId), rec);
        await audit.write({ id: crypto.randomUUID(), timestamp: rec.storedAt, action: 'interactions.readgrant.put', outcome: 'success', actor: { type: 'user', id: sessionSa }, subject: { type: 'app', id: clientId } });
        return json({ ok: true, clientId, hash: digest, resources });
      }

      // ── spec 341 §5.1b — the person's OUTBOUND MESSAGING rail: custody their messaging wire, and
      //    send under it. This is the half of `sendFromInbox` the Home cannot do: it can compose and
      //    it can write the sender's own copy, but the recipient's copy has to be an authorized,
      //    signed A2A delivery, and the key that signs it is here. Self-access only — a session
      //    proving some OTHER person is not authority over this person's mail. ──
      if (op === 'messaging.wireStatus' || op === 'messaging.wireEnable' || op === 'messaging.wireDisable' || op === 'messaging.send') {
        // WHO MAY DRIVE THIS RAIL. A person drives their own; an ORGANIZATION has no session of its
        // own and never will, so its rail is driven by a STEWARD presenting the org's stewardship
        // delegation — the same proof `consult.routingEnable` requires, verified the same way
        // (delegator is this org, delegate is the caller, stewardship SHAPE not merely member access
        // per SEC-C1, and ERC-1271-live against the org).
        //
        // The distinction is deliberate: a member-access grant is NOT authority to speak AS the
        // organization to the outside world.
        const isSelf = sessionSa.toLowerCase() === principal;
        const asSteward = isSelf ? false : await this.isSteward(principal, sessionSa, body.stewardship as IncomingDelegation | undefined);
        if (!isSelf && !asSteward) {
          return json({ error: 'only this agent, or a steward presenting its stewardship delegation, may drive its outbound rail' }, 403);
        }
        // The delegate every wire must name. Unprovisioned ⇒ 503 rather than a wire we cannot spend.
        let sessionKey: string;
        try { sessionKey = (await interactionsSessionAccount(this.env)).address.toLowerCase(); } catch {
          return json({ error: 'interactions-session key unprovisioned — messaging needs AKCS_INTERACTIONS_KEY_ID (agentic-kms) or GCP_KMS_INTERACTIONS_KEY_NAME (gcp-kms)' }, 503);
        }
        const rec = (await this.state.storage.get(MESSAGING_WIRE_KEY)) as MessagingWireRecord | undefined;

        if (op === 'messaging.wireStatus') {
          // Decoded from the wire, never stored beside it — see `wireTargets` for why the three
          // outcomes are distinguished rather than flattened to an empty list.
          // The TRANSPORT grant's targets, because that is the delegation the recipient's gate reads.
          const t = rec ? wireTargets(rec.transport, this.env.ALLOWED_TARGETS_ENFORCER) : null;
          return json({
            ok: true,
            sessionKey,
            wirePresent: !!rec,
            enabledAt: rec?.enabledAt ?? null,
            recipients: t?.ok ? t.targets : [],
            ...(t && !t.ok ? { wireDamaged: t.reason } : {}),
          });
        }

        if (op === 'messaging.wireDisable') {
          // LOCAL removal. Real revocation is on-chain and kills the wire at every recipient's gate;
          // this only stops us spending it. The distinction is stated because a caller who deletes
          // here has not revoked anything.
          await this.state.storage.delete(MESSAGING_WIRE_KEY);
          return json({ ok: true, note: 'local copy dropped — on-chain revocation is separate' });
        }

        if (op === 'messaging.wireEnable') {
          const incoming = body.delegation as IncomingDelegation | undefined;
          const incomingTransport = body.transport as IncomingDelegation | undefined;
          if (!incoming || !incomingTransport) {
            return json({ error: 'both the signing wire and the transport grant are required' }, 400);
          }
          const tsEnf = (this.env.TIMESTAMP_ENFORCER ?? '').toLowerCase();
          const amEnf = (this.env.ALLOWED_METHODS_ENFORCER ?? '').toLowerCase();
          const atEnf = (this.env.ALLOWED_TARGETS_ENFORCER ?? '').toLowerCase();
          if (![tsEnf, amEnf, atEnf].every((a) => /^0x[0-9a-f]{40}$/.test(a))) {
            return json({ error: 'messaging enforcers not configured — cannot verify the shapes' }, 503);
          }
          const chainIdForWire = Number(this.env.CHAIN_ID ?? 84532);
          const dm = this.env.DELEGATION_MANAGER as Address;
          const toD = (w: IncomingDelegation): Delegation =>
            ({ ...w, salt: BigInt(w.salt), caveats: w.caveats.map((c) => ({ enforcer: c.enforcer, terms: c.terms, args: (c.args ?? '0x') as Hex })) }) as Delegation;
          /** Signed by this person, and not already revoked. Fail-closed on a chain-read failure —
           *  storing an unverifiable delegation is how a junk-overwrite DoS starts. */
          const provenByPerson = async (w: IncomingDelegation): Promise<{ ok: true; digest: string } | { ok: false; res: Response }> => {
            const digest = hashDelegation(toD(w), chainIdForWire, dm);
            if (!(await this.erc1271(w.delegator as Address, digest, w.signature as Hex))) {
              return { ok: false, res: json({ error: 'signature failed verification against this person' }, 403) };
            }
            try {
              const revoked = (await this.pub().readContract({ address: dm, abi: IS_REVOKED_ABI, functionName: 'isRevoked', args: [digest] })) as boolean;
              if (revoked) return { ok: false, res: json({ error: 'this delegation is already revoked on-chain' }, 403) };
            } catch {
              return { ok: false, res: json({ error: 'revocation check unavailable — nothing stored (fail-closed)' }, 503) };
            }
            return { ok: true, digest };
          };

          // ── 1. The SIGNING wire (person → session key) ──────────────────────────────────────────
          if (incoming.delegator.toLowerCase() !== principal) {
            return json({ error: 'messaging wire delegator must be this person' }, 400);
          }
          // Without this, a caller could install a wire delegating to a key THEY control. It would be
          // a perfectly valid delegation — just not to us — and every downstream gate would agree.
          if (incoming.delegate.toLowerCase() !== sessionKey) {
            return json({ error: 'messaging wire delegate must be the interactions-session key' }, 400);
          }
          const shapeErr = checkSessionWireShape(incoming, { timestamp: tsEnf, allowedMethods: amEnf }, Math.floor(Date.now() / 1000), { skill: MESSAGING_DELIVER_SKILL });
          if (shapeErr) return json({ error: shapeErr }, 400);
          const wireProof = await provenByPerson(incoming);
          if (!wireProof.ok) return wireProof.res;

          // ── 2. The TRANSPORT grant (person → person) ────────────────────────────────────────────
          // Self-delegated by construction: it confers nothing new, it carries the caveats the
          // recipient's gate enforces. A grant whose delegate is anyone else would let some OTHER
          // party send as this person — the single most valuable thing to get wrong here.
          if (incomingTransport.delegator.toLowerCase() !== principal || incomingTransport.delegate.toLowerCase() !== principal) {
            return json({ error: 'the transport grant must be this person delegating to themselves' }, 400);
          }
          const tShape = checkSessionWireShape(incomingTransport, { timestamp: tsEnf, allowedMethods: amEnf }, Math.floor(Date.now() / 1000), { skill: MESSAGING_DELIVER_SKILL });
          if (tShape) return json({ error: `transport grant: ${tShape}` }, 400);
          // It must NAME its recipients. Without this caveat the grant is unbounded, and "approve this
          // contact" would be a client-side preference rather than an on-chain-revocable bound.
          const tTargets = wireTargets(incomingTransport, atEnf);
          if (!tTargets.ok || tTargets.targets.length === 0) {
            return json({ error: 'the transport grant must name its recipients (allowedTargets)' }, 400);
          }
          const transportProof = await provenByPerson(incomingTransport);
          if (!transportProof.ok) return transportProof.res;

          const stored: MessagingWireRecord = {
            wire: incoming,
            transport: incomingTransport,
            hash: wireProof.digest,
            transportHash: transportProof.digest,
            sessionKey,
            enabledAt: new Date().toISOString(),
          };
          await this.state.storage.put(MESSAGING_WIRE_KEY, stored);
          await audit.write({ id: crypto.randomUUID(), timestamp: stored.enabledAt, action: 'interactions.messaging.wireEnable', outcome: 'success', actor: { type: 'user', id: sessionSa }, subject: { type: 'delegation', id: transportProof.digest } });
          return json({ ok: true, hash: wireProof.digest, transportHash: transportProof.digest, recipients: tTargets.targets });
        }

        // ── messaging.send ──────────────────────────────────────────────────────────────────────
        // RESOLVE THE RECIPIENT BEFORE CHECKING FOR THE WIRE, even though the wire check is cheaper.
        // The refusal has to NAME who to approve, and for a name-addressed send this is the only party
        // that can resolve it. Answering "no wire" without the recipient made the client mint one
        // covering whatever it could guess — which was the sender themselves (caught by the e2e, and a
        // silent fallback of exactly the kind ADR-0013 forbids).
        const chainId = Number(this.env.CHAIN_ID ?? 84532);

        // WHO IS THIS FOR. Three CALLER-SELECTED ways to name the recipient, not a fallback chain
        // (ADR-0013): the caller picks one and it either answers or fails. `conversationId` alone is
        // the reply case, and it resolves from the OWNER'S OWN descriptor — never from anything the
        // counterparty sent — which is the rule `replyInConversation` established and the only reason
        // a reply cannot be redirected by the other party.
        let recipient = String(body.recipient ?? '').toLowerCase();
        let recipientName = String(body.recipientName ?? '').trim().toLowerCase();
        // Bare label → public agent name. The send is still to an address; this is the map.
        if (recipientName && !recipientName.includes('.')) recipientName = `${recipientName}.impact`;
        const convId = String(body.conversationId ?? '');
        if (!recipient && recipientName) {
          if (!this.env.RPC_URL || !this.env.AGENT_NAME_REGISTRY || !this.env.AGENT_NAME_UNIVERSAL_RESOLVER) {
            return json({ error: 'name resolution is not configured on this deployment' }, 503);
          }
          try {
            const resolved = await new AgentNamingClient({
              rpcUrl: this.env.RPC_URL,
              chainId,
              registry: this.env.AGENT_NAME_REGISTRY as Address,
              universalResolver: this.env.AGENT_NAME_UNIVERSAL_RESOLVER as Address,
            }).resolveName(recipientName);
            if (!resolved) return json({ error: `no agent claimed the name "${recipientName}"` }, 404);
            recipient = resolved.toLowerCase();
          } catch (e) {
            return json({ error: `name resolution failed: ${e instanceof Error ? e.message : String(e)}` }, 502);
          }
        }
        if (!recipient && convId && rec) {
          // Only reachable with a wire present: resolving a reply's counterparty costs a vault read,
          // and a caller with no wire cannot send to them either way.
          const doc = await this.readDoc<InboxDataV1>(grant, INBOX_RESOURCE, null as never);
          const descriptor = ((doc?.conversations ?? []) as ConversationDescriptorV1[]).find((d) => d.id === convId);
          if (!descriptor) return json({ error: 'unknown conversation' }, 404);
          const meCaip = caip10(chainId, principal as Address).toLowerCase();
          const others = descriptor.participants.filter((p) => String(p).toLowerCase() !== meCaip);
          if (others.length !== 1) return json({ error: 'reply requires a two-party conversation' }, 409);
          recipient = (String(others[0]).match(/0x[0-9a-fA-F]{40}$/)?.[0] ?? '').toLowerCase();
        }
        if (!/^0x[0-9a-f]{40}$/.test(recipient)) {
          return json({ error: 'recipient (address), recipientName, or conversationId required' }, 400);
        }
        // Now the refusal can name who to approve.
        if (!rec) {
          return json({ error: 'no messaging wire — sign one before sending (the ceremony is one prompt)', code: 'wire_absent', recipient, sessionKey }, 409);
        }

        // IS THIS RECIPIENT INSIDE THE WIRE. The far gate would answer this too, but only as an opaque
        // authorization failure. Answering here lets the UI do the right thing — run the one-prompt
        // ceremony that adds this counterparty — instead of showing "delivery rejected" for what is
        // simply a contact the person has not approved yet (§5.1: one prompt per NEW counterparty).
        const cover = wireTargets(rec.transport, this.env.ALLOWED_TARGETS_ENFORCER);
        if (!cover.ok) {
          // A damaged or unbounded wire is NOT "no contacts approved" — offering the approve-a-contact
          // ceremony for it would loop, because the ceremony cannot fix either.
          return json({ error: `messaging wire targets are ${cover.reason} — re-sign the wire` }, 409);
        }
        // spec 341 §5.5a — `org.apply` is a different PAYLOAD on the same rail: an application is not
        // an envelope, so there is nothing to build and nothing to record in the sender's own inbox.
        // The org's gate admits it and the org's grant writes it.
        const requestedSkill = String(body.skill ?? MESSAGING_DELIVER_SKILL);
        if (!cover.targets.includes(recipient as Address)) {
          // Exact address first, then the scope CLASSES (spec 341 §5.1c): a target entry that is the
          // naming registry covers any named recipient when the sender is named too; an org SA covers
          // its current members when both parties are. Same resolver the recipient's far gate runs —
          // this near check exists only so the refusal can name who to approve.
          const scoped = await messagingScopeCovers(messagingScopeDepsFromEnv(this.env as never), {
            targets: cover.targets,
            sender: principal,
            recipient,
            skill: requestedSkill,
          });
          if (!scoped) {
            return json({ error: 'your messaging wire does not cover this recipient — approve them once to send', code: 'recipient_not_in_wire', recipient, recipients: cover.targets, sessionKey }, 409);
          }
        }
        if (requestedSkill === 'org.apply') {
          const applicationMessage = String(body.applicationMessage ?? '').trim();
          if (!applicationMessage) return json({ error: 'applicationMessage required' }, 400);
          try {
            const out = await deliverOutbound({
              personSA: principal as Address,
              recipientSA: recipient as Address,
              transportGrant: rec.transport,
              signAsPerson: async (h: Hex) => {
                const acct = await interactionsSessionAccount(this.env);
                if (!acct.sign) throw new Error('interactions-session KMS account lacks raw-digest sign');
                return wrapSessionSignature(rec.wire, await acct.sign({ hash: h }));
              },
              payload: {
                message: applicationMessage,
                org: recipient,
                ...(body.subject ? { subject: String(body.subject) } : {}),
                ...(body.record && typeof body.record === 'object' ? { record: body.record } : {}),
              },
              skill: 'org.apply',
              transport: this.a2aTransport(),
            });
            await audit.write({ id: crypto.randomUUID(), timestamp: new Date().toISOString(), action: 'interactions.org.apply', outcome: 'success', actor: { type: 'user', id: sessionSa }, subject: { type: 'org', id: recipient } });
            return json({ ok: true, taskId: out.taskId, messageId: out.taskId });
          } catch (e) {
            const reason = e instanceof Error ? e.message : String(e);
            return json({ error: `application rejected by the organization: ${reason}` }, 409);
          }
        }

        // THE DM IS THE PAIR (spec 313 §2 amendment — the Slack model). A send that names no
        // conversation is not a new thread; it is the one direct-message thread between these two
        // agents, whose id is deterministic from the pair. Both sides mint the same id without
        // coordinating, so a first message racing from each end lands in ONE conversation, and "new
        // message to someone I already talk to" continues the DM instead of opening a fresh `conv_`.
        // An explicit `conversationId` (assistant replies, invites continuing a thread) still wins.
        const conversationId = body.conversationId
          ? String(body.conversationId)
          : await directConversationId(principal, recipient);
        const built = await buildOutboundMessage({
          from: caip10(chainId, principal as Address) as never,
          to: caip10(chainId, recipient as Address) as never,
          bodyText: String(body.bodyText ?? ''),
          ...(body.subject ? { subject: String(body.subject) } : {}),
          conversationId,
          ...(body.title ? { title: String(body.title) } : {}),
          ...(Array.isArray(body.contextRefs) ? { contextRefs: body.contextRefs as ContextRefV1[] } : {}),
        });
        if (!built.ok) return json({ error: built.error }, 400);
        const { envelope, descriptor, bodyBytes } = built;

        // RECIPIENT SIDE FIRST, fail-closed — `sendFromInbox`'s rule, kept: a send that the recipient
        // rejects leaves nothing in the sender's own record claiming it went out. The A2A gate at the
        // far end re-verifies EVERYTHING (targets, skill, window, ERC-1271, on-chain revocation), so
        // a stale or revoked wire stops the send rather than degrading it.
        let taskId: string;
        try {
          const out = await deliverOutbound({
            personSA: principal as Address,
            recipientSA: recipient as Address,
            transportGrant: rec.transport,
            // Sign as the PERSON: the KMS key produces the raw ECDSA, and the signing wire that
            // authorizes it is wrapped in alongside (`0x51`). The recipient unwraps and re-verifies
            // every leg per message — delegator is the claimed sender, the sig recovers to the
            // delegate, the wire is ERC-1271-valid and unrevoked.
            signAsPerson: async (h: Hex) => {
              const acct = await interactionsSessionAccount(this.env);
              if (!acct.sign) throw new Error('interactions-session KMS account lacks raw-digest sign');
              return wrapSessionSignature(rec.wire, await acct.sign({ hash: h }));
            },
            payload: { envelope: envelope as never, bodyText: new TextDecoder().decode(bodyBytes), conversation: descriptor },
            skill: MESSAGING_DELIVER_SKILL,
            transport: this.a2aTransport(),
          });
          taskId = out.taskId;
        } catch (e) {
          const reason = e instanceof Error ? e.message : String(e);
          await audit.write({ id: crypto.randomUUID(), timestamp: new Date().toISOString(), action: 'interactions.messaging.send', outcome: 'denied', actor: { type: 'user', id: sessionSa }, subject: { type: 'message', id: envelope.id }, reason }).catch(() => undefined);
          // NOT caught into a weaker path. The in-Worker `internal.deliver` marker would land this
          // message without any of the above being true, which is the authority this replaces.
          return json({ error: `delivery rejected by the recipient: ${reason}` }, 409);
        }

        // Self-send: the delivered copy IS the record. Writing a second one would double the thread.
        if (recipient === principal) {
          await audit.write({ id: crypto.randomUUID(), timestamp: envelope.createdAt, action: 'interactions.messaging.send', outcome: 'success', actor: { type: 'user', id: sessionSa }, subject: { type: 'message', id: envelope.id } });
          await this.recordOperation(body, 'send', envelope.id);
          return json({ ok: true, messageId: envelope.id, conversationId: envelope.conversationId, taskId });
        }

        // The sender's OWN copy — body under this person's delivery wire, envelope + `sent` event +
        // their own view of the thread under the interactions grant. Same pair of writes the
        // assistant reply path performs, serialized behind the same single-writer mutex.
        const dgSend = st.deliveryGrant;
        if (!dgSend) return json({ error: 'delivered, but no delivery grant to record your own copy — enable inbox delivery' }, 409);
        return this.serialize(async () => {
          const doc = (await this.readDoc<InboxDataV1>(grant, INBOX_RESOURCE, null as never)) ?? { version: 1, envelopes: [], events: [], draftCases: [], caseEvents: [], cards: {} } as unknown as InboxDataV1;
          let bin = '';
          for (const b of bodyBytes) bin += String.fromCharCode(b);
          await this.vaultFor(dgSend).write({ owner: '', resource: envelope.body.resource, data: { b64: btoa(bin), contentType: 'text/plain', bodyHash: envelope.bodyHash }, classification: 'internal' } as never);
          doc.envelopes = [...((doc.envelopes as MessageEnvelopeV1[] | undefined) ?? []), envelope as never];
          // Spec 400 W2 (B5) — what I said is searchable too.
          await this.indexForSearch(envelope.id, { kind: 'message', at: envelope.createdAt, snippet: '', ref: { conversationId: envelope.conversationId, messageId: envelope.id, from: principal } }, new TextDecoder().decode(bodyBytes));
          const sent: MessageEventV1 = { version: 'ap.message.event.v1', messageId: envelope.id, actor: envelope.from, eventType: 'sent', at: envelope.createdAt };
          doc.events = [...((doc.events as MessageEventV1[] | undefined) ?? []), sent];
          // The sender's own view of the thread — same descriptor, owned by them.
          upsertConversation(doc, { ...descriptor, owner: envelope.from });
          await this.writeDoc(grant, INBOX_RESOURCE, doc);
          await audit.write({ id: crypto.randomUUID(), timestamp: envelope.createdAt, action: 'interactions.messaging.send', outcome: 'success', actor: { type: 'user', id: sessionSa }, subject: { type: 'message', id: envelope.id } });
          await this.recordOperation(body, 'send', envelope.id);
          return json({ ok: true, messageId: envelope.id, conversationId: envelope.conversationId, taskId });
        });
      }

      // ── Topic participation ops (restricted topics; tbox/messaging.ttl §Topic participation) ──
      if (op === 'channels.participants' || op === 'channels.invite' || op === 'channels.acceptInvite' || op === 'channels.revokeParticipant') {
        const presence = await this.communityPresence(grant, principal, sessionSa, sessionCaip, body);
        const name = presence.you;
        const steward = presence.steward;
        const channelId = String(body.channelId ?? '');
        if (!channelId) return json({ error: 'channelId required' }, 400);
        const index = await this.readDoc<ChannelV1[]>(grant, CONVERSATION_INDEX_RESOURCE, []);
        const entry = index.find((c) => c.descriptor.id === channelId);
        if (!entry) return json({ error: 'unknown channel' }, 404);
        const policy = channelParticipationPolicy(entry);
        const topicInvites = (await this.readDoc<DiscussionInvitationRowV1[]>(grant, DISCUSSION_INVITATIONS_RESOURCE, []))
          .filter((i) => i.topicId === channelId && i.status === 'invited');
        const invitedHere = topicInvites.some((i) => i.invitedAgent.toLowerCase() === sessionSa.toLowerCase());
        // Accept / roster for an invitee is authorized by the invitation. Member-access (no listing)
        // is enough to see who is in a room they can already read — the listing gate made grant-holders
        // look like the room was empty and hid their own join banner.
        if (!presence.admitted && !invitedHere) {
          return json({ error: 'join this community first — publish a directory listing to enter its channels' }, 403);
        }

        if (op === 'channels.participants') {
          if (!canSeeChannel(entry, sessionSa, steward) && !invitedHere) return json({ error: 'not a participant of this restricted topic' }, 403);
          if (policy === 'open') {
            // OPEN ⇒ participation is DERIVED from org membership — render the org directory, never a
            // stored per-topic list (the aporg:memberOf doctrine).
            const now = new Date().toISOString();
            const rows = (await this.readDoc<IndexedListing[]>(grant, DIRECTORY_RESOURCE, [])).filter((l) => isListingCurrent(l.listing, now));
            return json({ ok: true, policy, participants: rows.map((l) => ({ personSA: l.listing.subject.toLowerCase().match(/0x[0-9a-f]{40}$/)?.[0] ?? l.listing.subject.toLowerCase(), personName: l.label, role: 'contributor', derived: true })) });
          }
          const rows = await this.readDoc<DiscussionParticipationRowV1[]>(grant, TOPIC_PARTICIPATION_RESOURCE(channelId), []);
          const invites = (await this.readDoc<DiscussionInvitationRowV1[]>(grant, DISCUSSION_INVITATIONS_RESOURCE, [])).filter((i) => i.topicId === channelId && i.status === 'invited');
          return json({ ok: true, policy, participants: rows.filter((r) => r.status === 'active'), pendingInvites: invites });
        }

        if (op === 'channels.acceptInvite') {
          // The INVITEE converts their invitation into a DiscussionParticipation situation. Serialize:
          // invitations doc + participation doc + descriptor projection are a multi-doc RMW.
          return this.serialize(async () => {
            const invites = await this.readDoc<DiscussionInvitationRowV1[]>(grant, DISCUSSION_INVITATIONS_RESOURCE, []);
            const inv = invites.find((i) => i.topicId === channelId && i.invitedAgent.toLowerCase() === sessionSa.toLowerCase() && i.status === 'invited');
            if (!inv) return json({ error: 'no pending invitation for you on this topic' }, 404);
            const now = new Date().toISOString();
            inv.status = 'accepted'; inv.decidedAt = now;
            const rows = (await this.readDoc<DiscussionParticipationRowV1[]>(grant, TOPIC_PARTICIPATION_RESOURCE(channelId), [])).filter((r) => r.personSA !== sessionSa.toLowerCase() || r.status !== 'active');
            rows.push({ personSA: sessionSa.toLowerCase(), ...(name ? { personName: name } : inv.invitedName ? { personName: inv.invitedName } : {}), role: inv.role, situationRef: `sit_dp_${crypto.randomUUID()}`, invitationRef: inv.id, acceptedAt: now, status: 'active' });
            // Refresh the members[] fast-ACL projection on the descriptor from the accepted participations.
            const fresh = await this.readDoc<ChannelV1[]>(grant, CONVERSATION_INDEX_RESOURCE, []);
            const fe = fresh.find((c) => c.descriptor.id === channelId);
            if (fe) { fe.members = [...new Set(rows.filter((r) => r.status === 'active').map((r) => r.personSA))]; await this.writeDoc(grant, CONVERSATION_INDEX_RESOURCE, fresh); }
            await this.writeDoc(grant, TOPIC_PARTICIPATION_RESOURCE(channelId), rows);
            await this.writeDoc(grant, DISCUSSION_INVITATIONS_RESOURCE, invites);
            await audit.write({ id: crypto.randomUUID(), timestamp: now, action: 'interactions.channels.accept-invite', outcome: 'success', actor: { type: 'user', id: sessionSa }, subject: { type: 'discussion-participation', id: `${channelId}:${sessionSa.toLowerCase()}` } });
            return json({ ok: true, role: inv.role });
          });
        }

        // invite + revoke are FACILITATOR acts: the steward/custodian, or an active participant whose
        // discussion-scoped role is facilitator (the topic creator seeds that on restricted create).
        if (policy !== 'restricted') return json({ error: 'open topics have no invitations — every organization member already participates' }, 400);
        const partRows = await this.readDoc<DiscussionParticipationRowV1[]>(grant, TOPIC_PARTICIPATION_RESOURCE(channelId), []);
        const facilitator = steward || partRows.some((r) => r.personSA === sessionSa.toLowerCase() && r.status === 'active' && r.role === 'facilitator');
        if (!facilitator) return json({ error: 'only a facilitator of this topic (or the organization custodian) may manage its participants' }, 403);

        if (op === 'channels.invite') {
          const invitedAgent = String(body.personSA ?? '').toLowerCase();
          if (!/^0x[0-9a-f]{40}$/.test(invitedAgent)) return json({ error: 'personSA (0x address) required' }, 400);
          // Topic invitations select among EXISTING organization members (a current directory
          // listing). Bringing a stranger in is MEMBERSHIP enrollment (spec 324 §12) — never a topic act.
          // A STEWARD may also invite someone the org already granted (inbound wire / role) whose
          // listing is missing or stale — they are not a new member; accept is still required.
          const nowInv = new Date().toISOString();
          const roster = (await this.readDoc<IndexedListing[]>(grant, DIRECTORY_RESOURCE, [])).filter((l) => isListingCurrent(l.listing, nowInv));
          if (!roster.some((l) => l.listing.subject.toLowerCase().endsWith(invitedAgent)) && !steward) {
            return json({ error: 'topic invitations are for existing organization members only — invite them to the organization first (membership enrollment)' }, 403);
          }
          const role: 'facilitator' | 'contributor' = body.role === 'facilitator' ? 'facilitator' : 'contributor';
          return this.serialize(async () => {
            const invites = await this.readDoc<DiscussionInvitationRowV1[]>(grant, DISCUSSION_INVITATIONS_RESOURCE, []);
            if (invites.some((i) => i.topicId === channelId && i.invitedAgent === invitedAgent && i.status === 'invited')) return json({ error: 'an invitation for this person is already pending' }, 409);
            if (partRows.some((r) => r.personSA === invitedAgent && r.status === 'active')) return json({ error: 'already a participant of this topic' }, 409);
            const inv: DiscussionInvitationRowV1 = {
              id: `dinv_${crypto.randomUUID()}`, topicId: channelId, invitedAgent,
              ...(body.personName ? { invitedName: String(body.personName) } : {}),
              invitedBy: sessionSa.toLowerCase(), ...(name ? { invitedByName: name } : {}),
              role, status: 'invited', createdAt: new Date().toISOString(),
            };
            invites.push(inv);
            await this.writeDoc(grant, DISCUSSION_INVITATIONS_RESOURCE, invites.slice(-500));
            await audit.write({ id: crypto.randomUUID(), timestamp: inv.createdAt, action: 'interactions.channels.invite', outcome: 'success', actor: { type: 'user', id: sessionSa }, subject: { type: 'discussion-invitation', id: inv.id } });
            // The CALLER sends the invitee's Home-inbox message with the discussion-topic contextRef —
            // the DO records the invitation artifact only.
            return json({ ok: true, inviteId: inv.id, topicTitle: entry.title });
          });
        }

        // channels.revokeParticipant — facilitator removes a participant (or cancels a pending invite).
        const personSA = String(body.personSA ?? '').toLowerCase();
        if (!/^0x[0-9a-f]{40}$/.test(personSA)) return json({ error: 'personSA (0x address) required' }, 400);
        return this.serialize(async () => {
          const now = new Date().toISOString();
          const rows = await this.readDoc<DiscussionParticipationRowV1[]>(grant, TOPIC_PARTICIPATION_RESOURCE(channelId), []);
          for (const r of rows) { if (r.personSA === personSA && r.status === 'active') { r.status = 'revoked'; r.revokedAt = now; } }
          const invites = await this.readDoc<DiscussionInvitationRowV1[]>(grant, DISCUSSION_INVITATIONS_RESOURCE, []);
          for (const i of invites) { if (i.topicId === channelId && i.invitedAgent === personSA && i.status === 'invited') { i.status = 'revoked'; i.decidedAt = now; } }
          const fresh = await this.readDoc<ChannelV1[]>(grant, CONVERSATION_INDEX_RESOURCE, []);
          const fe = fresh.find((c) => c.descriptor.id === channelId);
          if (fe) { fe.members = [...new Set(rows.filter((r) => r.status === 'active').map((r) => r.personSA))]; await this.writeDoc(grant, CONVERSATION_INDEX_RESOURCE, fresh); }
          await this.writeDoc(grant, TOPIC_PARTICIPATION_RESOURCE(channelId), rows);
          await this.writeDoc(grant, DISCUSSION_INVITATIONS_RESOURCE, invites);
          await audit.write({ id: crypto.randomUUID(), timestamp: now, action: 'interactions.channels.revoke-participant', outcome: 'success', actor: { type: 'user', id: sessionSa }, subject: { type: 'discussion-participation', id: `${channelId}:${personSA}` } });
          return json({ ok: true });
        });
      }

      if (op === 'grants.list') {
        // Steward-or-self visibility into the issuance ledger (spec 322 W3e).
        const self = sessionSa.toLowerCase() === principal;
        const steward = self ? false : await this.isSteward(principal, sessionSa, body.stewardship as IncomingDelegation | undefined);
        if (!self && !steward) return json({ error: 'stewardship proof required' }, 403);
        return json({ ok: true, grants: st.ledger ?? [] });
      }

      // ── Person-plane ops (spec 322 W3d) — STRICTLY self: the session SA must BE the principal. ──
      if (op === 'relationships.get' || op === 'relationships.merge' || op === 'member.profile.put') {
        if (sessionSa.toLowerCase() !== principal) return json({ error: 'this record belongs to the principal — self access only' }, 403);
        if (op === 'relationships.get') {
          const doc = await this.readDoc<RelationshipsDocV1>(grant, RELATIONSHIPS_RESOURCE, { orgs: {} });
          return json({ ok: true, relationships: doc });
        }
        if (op === 'relationships.merge') {
          const entry = body.entry as Partial<RelationshipEntryV1> | undefined;
          const org = String(entry?.org ?? '').toLowerCase();
          if (!/^0x[0-9a-fA-F]{40}$/.test(org)) return json({ error: 'entry.org (address) required' }, 400);
          const doc = await this.readDoc<RelationshipsDocV1>(grant, RELATIONSHIPS_RESOURCE, { orgs: {} });
          if (body.remove === true) delete doc.orgs[org];
          else {
            const prev = doc.orgs[org];
            doc.orgs[org] = {
              org,
              // steward ⊇ member: a subsequent 'member' merge must NEVER downgrade an existing steward (spec
              // 324 W3 fix — recording the creator as a member was silently stripping their steward inbox
              // control, resolveInboxOwner then 403'd them from their own application queue).
              //
              // 'self' sits OUTSIDE that order rather than above or below it. A persona — another name
              // for the same human — is not a stronger stewardship or a weaker membership; there is no
              // second party in it at all. So it is sticky in both directions: once an entry says the
              // agent is this person, no later merge that merely forgot to say so turns it into a
              // relationship with somebody else. Without this the coercion below read 'self' as
              // 'member', and a persona came back as an org the person is a member of.
              relationship:
                entry?.relationship === 'self' || prev?.relationship === 'self' ? 'self'
                : entry?.relationship === 'steward' || prev?.relationship === 'steward' ? 'steward'
                : 'member',
              ...(entry?.orgName ? { orgName: String(entry.orgName) } : {}),
              ...(entry?.kind ? { kind: String(entry.kind) } : prev?.kind ? { kind: prev.kind } : {}),
              ...(entry?.parent ? { parent: String(entry.parent).toLowerCase() } : prev?.parent ? { parent: prev.parent } : {}),
              // spec 324 W3 — provenance back to the authoritative OrganizationMembership Situation.
              ...(entry?.membershipId ? { membershipId: String(entry.membershipId) } : prev?.membershipId ? { membershipId: prev.membershipId } : {}),
              ...(entry?.membershipSituationHash ? { membershipSituationHash: String(entry.membershipSituationHash) } : prev?.membershipSituationHash ? { membershipSituationHash: prev.membershipSituationHash } : {}),
              ...(entry?.enrollmentDecisionRef ? { enrollmentDecisionRef: String(entry.enrollmentDecisionRef) } : prev?.enrollmentDecisionRef ? { enrollmentDecisionRef: prev.enrollmentDecisionRef } : {}),
              ...(entry?.delegationHash ? { delegationHash: String(entry.delegationHash) } : {}),
              // Wires accumulate (a member-access grant may arrive after the membership entry);
              // self-gated op — only the person can place credentials in their own doc.
              ...(Array.isArray(entry?.delegations) || prev?.delegations
                ? { delegations: [...(prev?.delegations ?? []), ...((entry?.delegations as IncomingDelegation[] | undefined) ?? [])].slice(-8) }
                : {}),
              updatedAt: new Date().toISOString(),
            };
          }
          await audit.write({ id: crypto.randomUUID(), timestamp: new Date().toISOString(), action: 'interactions.relationships.merge', outcome: 'success', actor: { type: 'user', id: sessionSa }, subject: { type: 'org-link', id: org } });
          await this.writeDoc(grant, RELATIONSHIPS_RESOURCE, doc);
          return json({ ok: true });
        }
        const org = String(body.org ?? '').toLowerCase();
        if (!/^0x[0-9a-fA-F]{40}$/.test(org)) return json({ error: 'org (address) required' }, 400);
        const profile = (body.profile ?? {}) as Record<string, unknown>;
        await audit.write({ id: crypto.randomUUID(), timestamp: new Date().toISOString(), action: 'interactions.member-profile.put', outcome: 'success', actor: { type: 'user', id: sessionSa }, subject: { type: 'member-profile', id: org } });
        await this.writeDoc(grant, MEMBER_PROFILE_RESOURCE(org), profile);
        return json({ ok: true });
      }

      // ── spec 328 — the person's auto-reply inbox assistant (owner-controlled; STRICTLY self:
      //    an org steward or relying app cannot enable someone's assistant). Config + playbook are
      //    vault records under the existing `conversation.topic:*` scope; the DO keeps only the
      //    O(1) gate flag + the seen ledger (caches/dedup, never the source of truth). ──
      if (op === 'inbox.assistantGet' || op === 'inbox.assistantEnable' || op === 'inbox.assistantDisable') {
        if (sessionSa.toLowerCase() !== principal) return json({ error: 'the inbox assistant belongs to the principal — self access only' }, 403);
        if (op === 'inbox.assistantGet') {
          const cfg = await this.readDoc<PersonAssistantV1 | null>(grant, PERSON_ASSISTANT_RESOURCE, null);
          return json({ ok: true, assistant: cfg });
        }
        if (op === 'inbox.assistantDisable') {
          const cfg = await this.readDoc<PersonAssistantV1 | null>(grant, PERSON_ASSISTANT_RESOURCE, null);
          if (cfg) await this.writeDoc(grant, PERSON_ASSISTANT_RESOURCE, { ...cfg, enabled: false });
          await this.state.storage.delete(INBOX_ASSISTANT_FLAG_KEY);
          await audit.write({ id: crypto.randomUUID(), timestamp: new Date().toISOString(), action: 'interactions.inbox.assistantDisable', outcome: 'success', actor: { type: 'user', id: sessionSa }, subject: { type: 'inbox', id: principal } });
          return json({ ok: true });
        }
        // inbox.assistantEnable — capture the person's primary name ONCE at enable time (ADR-0012:
        // one reverseResolve view call; re-enabling refreshes after a name rotation). A resolver
        // failure fails the ceremony closed — never a silently nameless assistant (ADR-0013).
        let primaryName: string | null = null;
        if (this.env.RPC_URL && this.env.AGENT_NAME_REGISTRY && this.env.AGENT_NAME_UNIVERSAL_RESOLVER) {
          try {
            primaryName = await new AgentNamingClient({
              rpcUrl: this.env.RPC_URL,
              chainId: Number(this.env.CHAIN_ID ?? 84532),
              registry: this.env.AGENT_NAME_REGISTRY as Address,
              universalResolver: this.env.AGENT_NAME_UNIVERSAL_RESOLVER as Address,
            }).reverseResolve(principal as Address);
          } catch (e) {
            return json({ error: `could not resolve your primary name: ${e instanceof Error ? e.message : String(e)}` }, 502);
          }
        }
        const displayName = primaryName ?? String(body.displayName ?? '').trim();
        if (!displayName) return json({ error: 'you have no primary name to reply as — claim a name first, or supply a displayName' }, 409);
        const cfg: PersonAssistantV1 = { version: 'ap.person-assistant.v1', enabled: true, trigger: 'all', displayName, enabledBy: sessionSa.toLowerCase(), enabledAt: new Date().toISOString() };
        // Seed the seen ledger from the CURRENT inbox so pre-enable history NEVER triggers (§3).
        const inboxDoc = await this.readDoc<{ envelopes?: MessageEnvelopeV1[] }>(grant, INBOX_RESOURCE, {});
        await this.state.storage.put(INBOX_ASSISTANT_SEEN_KEY, ((inboxDoc.envelopes ?? []).map((e) => e.id)).slice(-INBOX_ASSISTANT_SEEN_CAP));
        await audit.write({ id: crypto.randomUUID(), timestamp: cfg.enabledAt, action: 'interactions.inbox.assistantEnable', outcome: 'success', actor: { type: 'user', id: sessionSa }, subject: { type: 'inbox', id: principal } });
        await this.writeDoc(grant, PERSON_ASSISTANT_RESOURCE, cfg);
        await this.state.storage.put(INBOX_ASSISTANT_FLAG_KEY, true); // gate cache LAST — never flags an unwritten config
        return json({ ok: true, assistant: cfg });
      }

      // ── Owner-own capability records (spec 323 W2) — STRICTLY self; whitelisted recordType. ──
      // `record.get`/`record.put { record }`: the delegation-authorized, KEK-encrypted home for the
      // person's own profile/skills/manifest, replacing the V-1 bearer path + app-local KV. The
      // interactions grant's record scope + the vault's KEK gate BOTH bound this at demo-mcp; the
      // self-check + whitelist here are the belt to those suspenders.
      if (op === 'record.list') {
        // spec 315 vault viewer — the person enumerates their OWN Home-managed vault records (self-gated).
        // demo-mcp's list is record-scope-filtered to the interactions grant, so app-specific records under
        // other grants never appear (least-privilege).
        if (sessionSa.toLowerCase() !== principal) return json({ error: 'this vault belongs to the principal — self access only' }, 403);
        // spec 341 §4.3b — NOT for relying apps, and this is a pre-existing exposure the per-app work
        // surfaced rather than created. This block has accepted relying id_tokens since before per-app
        // grants existed, and `sessionSa === principal` is TRUE for any app holding the person's token
        // — the subject IS the person. So enumeration was reachable by every connected app, under the
        // broad interactions grant, which is precisely what scoped grants exist to prevent: an app that
        // may read ONE record family could still learn every record type the person has.
        //
        // Reading a named record under a scoped grant is `record.get`. There is no scoped form of
        // "list everything", so there is nothing to widen to — this is refused, not deferred.
        if (skillsClientId) {
          return json({ error: 'enumerating this vault is the owner’s own operation — an app reads named records under its grant', code: 'read_grant_no_enumerate' }, 403);
        }
        const records = await this.vaultFor(grant).list('');
        return json({ ok: true, records });
      }
      if (op === 'record.get' || op === 'record.put') {
        if (sessionSa.toLowerCase() !== principal) return json({ error: 'this record belongs to the principal — self access only' }, 403);
        const recordType = String(body.recordType ?? '');
        if (!recordType) return json({ error: 'recordType required' }, 400);
        // spec 341 §4.3b — A RELYING APP READS UNDER ITS OWN GRANT.
        //
        // This is what lets an app read a person's PRIVATE CAPABILITY RECORD (`skills.data`) without
        // being handed the broad interactions grant that reaches everything else. `readgrant.put` could
        // already store such a grant; until now nothing consumed one, so a capability-scoped grant was
        // issuable and inert.
        //
        // WRITES STAY OFF THIS RAIL, permanently as far as this op is concerned. A read grant is
        // read-only by construction (`ops: ['read']`), so an app presenting one cannot write — but
        // relying on demo-mcp to refuse would mean the request is made and the refusal arrives from a
        // hop away. Refused here, by identity, so the boundary is visible where the decision is.
        let recordGrant = grant;
        if (skillsClientId) {
          if (op === 'record.put') {
            return json({ error: 'a relying app may read records, never write them', code: 'read_grant_read_only' }, 403);
          }
          const rec = (await this.state.storage.get(READ_GRANT_KEY(skillsClientId))) as ReadGrantRecord | undefined;
          if (!rec) {
            return json({ error: 'this app has no read grant — the person authorizes it once, and can revoke it alone', code: 'read_grant_absent', clientId: skillsClientId }, 409);
          }
          try {
            const revoked = (await this.pub().readContract({ address: this.env.DELEGATION_MANAGER as Address, abi: IS_REVOKED_ABI, functionName: 'isRevoked', args: [rec.hash as Hex] })) as boolean;
            if (revoked) return json({ error: 'this app’s read grant was revoked', code: 'read_grant_revoked', clientId: skillsClientId }, 403);
          } catch {
            return json({ error: 'revocation check unavailable — read refused (fail-closed)' }, 503);
          }
          // The record IS the resource here, so coverage is checked directly rather than through
          // `OP_RESOURCE`: `record.get` touches whatever the caller names, which is exactly why an app
          // must not inherit a grant scoped for something else.
          const need = `vault:${recordType}`;
          let covered = false;
          try {
            const scopeCav = (rec.wire.caveats ?? []).find((c) => (c.enforcer ?? '').toLowerCase() === VAULT_RECORD_SCOPE_ENFORCER.toLowerCase());
            const granted = scopeCav?.terms ? decodeVaultRecordScopeTerms(scopeCav.terms as Hex).flatMap((gr) => gr.resources) : [];
            covered = granted.some((r) => (r.endsWith('*') ? need.startsWith(r.slice(0, -1)) : r === need));
          } catch { covered = false; }
          if (!covered) {
            return json({ error: `this app's read grant does not cover ${need}`, code: 'read_grant_scope', clientId: skillsClientId, need }, 403);
          }
          recordGrant = rec.wire;
        }
        // WRITES stay whitelisted (only the known capability records may be written from here). READS defer
        // to demo-mcp's record-scope gate (the interactions grant's scope) so the vault viewer (spec 315)
        // can VIEW any Home-managed record; an out-of-scope record is denied at demo-mcp, never silently.
        // The self-check above + the KEK gate + the grant scope remain.
        // The person's OWN card-room study records — their style in their words, their reads on players, and
        // the coach's notes in their cabinet — are theirs to write here too (`card-room.ts`); the hand record is
        // written by the arrangement (the agent at hand end), never by hand.
        // The coach's notes are in HER cabinet and are hers to clear (a wrong note is hers to remove, a fired
        // coach's notes are hers to keep or drop); the hand record is written by the arrangement only.
        const ownStudyRecord = /^cardroom\.(?:[a-z0-9-]+\.)?(style|read|note)$/.test(recordType) || recordType === 'cardroom.profile';
        // Spec 410 §1.2 — the rotation ceremony's own writes, by the person over her session: a wire's lineage
        // (`delegation.lineage:<hash>`, the head a delegate refreshes to) and a contact's re-issued wire (`contact:<sa>`).
        // Found live: the ceremony wrote lineage through this op and this gate refused it, so every re-issued wire was
        // "recorded" as a warning. Self-gated like the rest; the record is hers.
        const ownRotationRecord = recordType.startsWith('delegation.lineage:') || recordType.startsWith('contact:');
        if (op === 'record.put' && !CAPABILITY_RECORDS.has(recordType) && !recordType.startsWith('content.') && !ownStudyRecord && !ownRotationRecord) {
          return json({ error: `recordType must be a capability record, a content.* record, the person's own cardroom.style / cardroom.read, or a rotation record (delegation.lineage:*, contact:*)` }, 400);
        }
        if (op === 'record.get') {
          const r = await this.vaultFor(recordGrant).read<unknown>({ owner: '', resource: recordType });
          return json({ ok: true, record: r?.data ?? null });
        }
        if (body.record === undefined) return json({ error: 'record required' }, 400);
        await audit.write({ id: crypto.randomUUID(), timestamp: new Date().toISOString(), action: 'interactions.record.put', outcome: 'success', actor: { type: 'user', id: sessionSa }, subject: { type: 'record', id: recordType } });
        await this.vaultFor(grant).write({ owner: '', resource: recordType, data: body.record, classification: 'internal' } as never);
        return json({ ok: true });
      }

      // ── OrganizationMembership record (spec 324 W3) — STRICTLY self; the AUTHORITATIVE membership Situation
      //    + credential per org, in the principal's OWN vault. Membership ≠ Delegation ≠ Listing (ADR-0048
      //    #3/#6): this is the single source of truth the related:*/directory/gate projections point back to.
      //    Writing it grants NO authority — the delegations issued *because of* membership are separate. ──
      if (op === 'membership.get' || op === 'membership.put') {
        if (sessionSa.toLowerCase() !== principal) return json({ error: 'this membership record belongs to the principal — self access only' }, 403);
        const org = String(body.org ?? '').toLowerCase();
        if (!/^0x[0-9a-fA-F]{40}$/.test(org)) return json({ error: 'org (address) required' }, 400);
        if (op === 'membership.get') {
          const r = await this.vaultFor(grant).read<unknown>({ owner: '', resource: MEMBERSHIP_RESOURCE(org) });
          return json({ ok: true, membership: r?.data ?? null });
        }
        if (body.membership === undefined) return json({ error: 'membership (SituationV2) required' }, 400);
        await audit.write({ id: crypto.randomUUID(), timestamp: new Date().toISOString(), action: 'interactions.membership.put', outcome: 'success', actor: { type: 'user', id: sessionSa }, subject: { type: 'org-membership', id: org } });
        await this.vaultFor(grant).write({ owner: '', resource: MEMBERSHIP_RESOURCE(org), data: { membership: body.membership, credential: body.credential ?? null }, classification: 'internal' } as never);
        return json({ ok: true });
      }

      // ── spec 329 §2.1 — consultability grant custody (member → org) on the ORG's DO. The wire
      //    is a capability and lives WITH its delegate service (the org SA is the delegate; this
      //    DO is the org's execution point — the spec-322 §2 / 323 W3 custody rule), keyed by the
      //    spec's record name `org.consult-grant:<memberSA>`. NOTE (deviation from §2.1's vault
      //    residency, recorded in the spec): the deployed grant scopes cover no
      //    `vault:org.consult-grant:*` resource, and widening them forces a fleet-wide re-enable
      //    ceremony — so W1 custodies the wire in DO storage under the SAME key; W2's
      //    `find_members` eligibility read comes here. Fail-closed verification at store time:
      //    self-consent (session SA === delegator), delegate === this org, allowedTargets ===
      //    [the member], allowedMethods === the `discussion.consult` selector ONLY (never
      //    A2A_ANY_SKILL), timestamp caveat present, ERC-1271 + unrevoked on-chain. The MEMBER's
      //    A2A gate re-verifies everything again per message — this store is eligibility, never
      //    the authority (the delegation itself is).
      if (op === 'archetype.grantPut' || op === 'archetype.grantStatus' || op === 'archetype.grantRevoke') {
        // THE ARCHETYPE DISPATCH GRANT, stored by the CALLER against the HOST that minted it.
        //
        // Direction is the opposite of consult and worth restating: the delegator is the org that
        // HOSTS the archetypes and will spend its agent budget, so this store holds someone else's
        // opt-in to being asked. A steward of THIS org accepts it; nothing here can mint it.
        //
        // Verified before storage for the same reason consult is: an unverifiable wire stored now is
        // a mysterious refusal at the host's gate later, and the caller would have no way to tell a
        // bad grant from a host that changed its mind. This store is ELIGIBILITY, never authority —
        // the host's A2A gate re-verifies all of it per message.
        const steward = await this.isSteward(principal, sessionSa, body.stewardship as IncomingDelegation | undefined);
        if (!steward) return json({ error: 'only a steward of this organization may manage its archetype dispatch grants' }, 403);

        if (op === 'archetype.grantStatus') {
          const host = String(body.host ?? '').toLowerCase();
          if (!/^0x[0-9a-f]{40}$/.test(host)) return json({ error: 'host (address) required' }, 400);
          // Metadata only — the wire itself never leaves the DO (capability hygiene).
          const rec = (await this.state.storage.get(archetypeGrantRecordKey(host))) as
            { grantedAt?: string; archetypes?: string[]; hash?: string } | undefined;
          return json({ ok: true, granted: !!rec, grantedAt: rec?.grantedAt ?? null, archetypes: rec?.archetypes ?? [] });
        }
        if (op === 'archetype.grantRevoke') {
          const host = String(body.host ?? '').toLowerCase();
          if (!/^0x[0-9a-f]{40}$/.test(host)) return json({ error: 'host (address) required' }, 400);
          await this.state.storage.delete(archetypeGrantRecordKey(host));
          await audit.write({ id: crypto.randomUUID(), timestamp: new Date().toISOString(), action: 'interactions.archetype.grantRevoke', outcome: 'success', actor: { type: 'user', id: sessionSa }, subject: { type: 'archetype-grant', id: `${principal}:${host}` } });
          // Local forget only. The HOST's on-chain revocation is what actually withdraws authority;
          // this just stops us presenting a wire we no longer intend to use.
          return json({ ok: true, forgotten: true });
        }

        const wire = body.delegation as IncomingDelegation | undefined;
        if (!wire?.signature || !wire.delegator || !wire.delegate) return json({ error: 'signed archetype dispatch delegation required' }, 400);
        const host = wire.delegator.toLowerCase();
        if (wire.delegate.toLowerCase() !== principal) return json({ error: 'archetype grant delegate must be this organization' }, 400);
        if (host === principal) return json({ error: 'self-dispatch needs no grant — refusing to store one' }, 400);

        const tsEnf = (this.env.TIMESTAMP_ENFORCER ?? '').toLowerCase();
        const atEnf = (this.env.ALLOWED_TARGETS_ENFORCER ?? '').toLowerCase();
        const amEnf = (this.env.ALLOWED_METHODS_ENFORCER ?? '').toLowerCase();
        if (![tsEnf, atEnf, amEnf].every((a) => /^0x[0-9a-f]{40}$/.test(a))) {
          return json({ error: 'archetype grant enforcers not configured — cannot verify the grant shape' }, 503);
        }
        const caveats = wire.caveats ?? [];
        const byEnforcer = (addr: string) => caveats.find((c) => (c.enforcer ?? '').toLowerCase() === addr);
        if (!byEnforcer(tsEnf)) return json({ error: 'archetype grant must be timestamp-bounded' }, 400);
        const atCav = byEnforcer(atEnf);
        const amCav = byEnforcer(amEnf);
        if (!atCav?.terms || !amCav?.terms) return json({ error: 'archetype grant must carry allowedTargets + allowedMethods caveats' }, 400);
        let selectors: string[] = [];
        try {
          const targets = decodeAllowedTargetsTerms(atCav.terms as Hex).map((t) => t.toLowerCase());
          if (targets.length !== 1 || targets[0] !== host) {
            return json({ error: 'archetype grant allowedTargets must name exactly the host organization' }, 400);
          }
          selectors = decodeAllowedMethodsTerms(amCav.terms as Hex).map((x) => x.toLowerCase());
          if (selectors.some((x) => x === A2A_ANY_SKILL.toLowerCase())) {
            return json({ error: 'archetype grant must never carry the any-skill sentinel' }, 400);
          }
          if (selectors.length === 0) return json({ error: 'archetype grant authorizes no method' }, 400);
        } catch {
          return json({ error: 'archetype grant caveat terms are undecodable' }, 400);
        }
        // Which archetypes those selectors mean, resolved by TRIAL DERIVATION over the names the
        // caller says it expects. A selector is a one-way hash, so a grant cannot be read back into
        // role names on its own — and storing selectors we cannot name would leave a steward unable
        // to see what they accepted. Unmatched selectors stay authorized; they are simply unnamed.
        const expect = Array.isArray(body.archetypes) ? body.archetypes.map((x: unknown) => String(x ?? '').trim().toLowerCase()).filter(Boolean) : [];
        const named = expect.filter((slug) => selectors.includes(skillSelector(`archetype.${slug}`).toLowerCase()));

        const d: Delegation = { ...wire, salt: BigInt(wire.salt), caveats: wire.caveats.map((c) => ({ enforcer: c.enforcer, terms: c.terms, args: (c.args ?? '0x') as Hex })) } as Delegation;
        const digest = hashDelegation(d, Number(this.env.CHAIN_ID ?? 84532), this.env.DELEGATION_MANAGER as Address);
        if (!(await this.erc1271(wire.delegator as Address, digest, wire.signature as Hex))) {
          return json({ error: 'archetype grant signature failed verification against the host organization' }, 403);
        }
        try {
          const revoked = (await this.pub().readContract({ address: this.env.DELEGATION_MANAGER as Address, abi: IS_REVOKED_ABI, functionName: 'isRevoked', args: [digest] })) as boolean;
          if (revoked) return json({ error: 'archetype grant is already revoked on-chain' }, 403);
        } catch { return json({ error: 'revocation check unavailable — grant not stored (fail-closed)' }, 503); }

        const grantedAt = new Date().toISOString();
        await this.state.storage.put(archetypeGrantRecordKey(host), { wire, host, grantedAt, hash: digest, archetypes: named, selectors });
        await audit.write({ id: crypto.randomUUID(), timestamp: grantedAt, action: 'interactions.archetype.grantPut', outcome: 'success', actor: { type: 'user', id: sessionSa }, subject: { type: 'archetype-grant', id: `${principal}:${host}` } });
        return json({ ok: true, grantedAt, host, archetypes: named, methods: selectors.length });
      }
      if (op === 'consult.grantPut' || op === 'consult.grantStatus' || op === 'consult.grantRevoke') {
        if (op === 'consult.grantPut') {
          const wire = body.delegation as IncomingDelegation | undefined;
          if (!wire?.signature || !wire.delegator || !wire.delegate) return json({ error: 'signed consultability delegation required' }, 400);
          const member = wire.delegator.toLowerCase();
          // The member consents for THEMSELVES only (the same self gate as inbox.assistantEnable).
          if (sessionSa.toLowerCase() !== member) return json({ error: 'consultability is the member\'s own consent — self grant only' }, 403);
          if (wire.delegate.toLowerCase() !== principal) return json({ error: 'consult grant delegate must be this organization' }, 400);
          // Caveat shape (spec 329 §2.1): allowedTargets = [memberSA]; allowedMethods = [consult
          // selector] (never the any-skill sentinel); timestamp-bounded. Fail closed on missing
          // enforcer config — an unverifiable shape is never stored.
          const tsEnf = (this.env.TIMESTAMP_ENFORCER ?? '').toLowerCase();
          const atEnf = (this.env.ALLOWED_TARGETS_ENFORCER ?? '').toLowerCase();
          const amEnf = (this.env.ALLOWED_METHODS_ENFORCER ?? '').toLowerCase();
          if (![tsEnf, atEnf, amEnf].every((a) => /^0x[0-9a-f]{40}$/.test(a))) {
            return json({ error: 'consult grant enforcers not configured — cannot verify the grant shape' }, 503);
          }
          const caveats = wire.caveats ?? [];
          const byEnforcer = (addr: string) => caveats.find((c) => (c.enforcer ?? '').toLowerCase() === addr);
          if (!byEnforcer(tsEnf)) return json({ error: 'consult grant must be timestamp-bounded' }, 400);
          const atCav = byEnforcer(atEnf);
          const amCav = byEnforcer(amEnf);
          if (!atCav?.terms || !amCav?.terms) return json({ error: 'consult grant must carry allowedTargets + allowedMethods caveats' }, 400);
          try {
            const targets = decodeAllowedTargetsTerms(atCav.terms as Hex).map((t) => t.toLowerCase());
            if (targets.length !== 1 || targets[0] !== member) return json({ error: 'consult grant allowedTargets must name exactly the member agent' }, 400);
            const selectors = decodeAllowedMethodsTerms(amCav.terms as Hex).map((s) => s.toLowerCase());
            const want = skillSelector(CONSULT_SKILL_ID).toLowerCase();
            if (selectors.some((s) => s === A2A_ANY_SKILL.toLowerCase())) return json({ error: 'consult grant must never carry the any-skill sentinel' }, 400);
            if (selectors.length !== 1 || selectors[0] !== want) return json({ error: 'consult grant allowedMethods must name exactly the discussion.consult selector' }, 400);
          } catch {
            return json({ error: 'consult grant caveat terms are undecodable' }, 400);
          }
          // ERC-1271 against the member + unrevoked on-chain (fail-closed junk-overwrite guard).
          const d: Delegation = { ...wire, salt: BigInt(wire.salt), caveats: wire.caveats.map((c) => ({ enforcer: c.enforcer, terms: c.terms, args: (c.args ?? '0x') as Hex })) } as Delegation;
          const digest = hashDelegation(d, Number(this.env.CHAIN_ID ?? 84532), this.env.DELEGATION_MANAGER as Address);
          if (!(await this.erc1271(wire.delegator as Address, digest, wire.signature as Hex))) {
            return json({ error: 'consult grant signature failed verification against the member' }, 403);
          }
          try {
            const revoked = (await this.pub().readContract({ address: this.env.DELEGATION_MANAGER as Address, abi: IS_REVOKED_ABI, functionName: 'isRevoked', args: [digest] })) as boolean;
            if (revoked) return json({ error: 'consult grant is already revoked on-chain' }, 403);
          } catch { return json({ error: 'revocation check unavailable — grant not stored (fail-closed)' }, 503); }
          const grantedAt = new Date().toISOString();
          await this.state.storage.put(consultGrantRecordKey(member), { wire, member, grantedAt, hash: digest });
          st.ledger = [...(st.ledger ?? []), { hash: digest, delegate: principal, resources: [consultGrantRecordKey(member)], storedAt: grantedAt }].slice(-50);
          await this.state.storage.put('state', st);
          await audit.write({ id: crypto.randomUUID(), timestamp: grantedAt, action: 'interactions.consult.grantPut', outcome: 'success', actor: { type: 'user', id: sessionSa }, subject: { type: 'consult-grant', id: `${principal}:${member}` } });
          return json({ ok: true, grantedAt });
        }
        if (op === 'consult.grantStatus') {
          // Self (the member asking about their own grant) or the org steward. Metadata only —
          // the wire itself never leaves the DO (capability hygiene).
          const member = String(body.member ?? sessionSa).toLowerCase();
          const self = sessionSa.toLowerCase() === member;
          const steward = self ? false : await this.isSteward(principal, sessionSa, body.stewardship as IncomingDelegation | undefined);
          if (!self && !steward) return json({ error: 'consult grant status is self-or-steward only' }, 403);
          const rec = (await this.state.storage.get(consultGrantRecordKey(member))) as { grantedAt?: string } | undefined;
          return json({ ok: true, granted: !!rec, grantedAt: rec?.grantedAt ?? null });
        }
        // consult.grantRevoke — the member withdraws their opt-in (or the steward clears it).
        // Removal here is the ORG-side eligibility kill (immediate: W2's find_members reads this
        // store); the on-chain revocation — the authority kill at the MEMBER's gate — is the
        // member's own client-side act (revokeGrantedDelegation), mirroring org-member-remove.
        const member = String(body.member ?? sessionSa).toLowerCase();
        if (!/^0x[0-9a-f]{40}$/.test(member)) return json({ error: 'member (address) required' }, 400);
        const self = sessionSa.toLowerCase() === member;
        const steward = self ? false : await this.isSteward(principal, sessionSa, body.stewardship as IncomingDelegation | undefined);
        if (!self && !steward) return json({ error: 'consult grant revoke is self-or-steward only' }, 403);
        await this.state.storage.delete(consultGrantRecordKey(member));
        await audit.write({ id: crypto.randomUUID(), timestamp: new Date().toISOString(), action: 'interactions.consult.grantRevoke', outcome: 'success', actor: { type: 'user', id: sessionSa }, subject: { type: 'consult-grant', id: `${principal}:${member}` } });
        return json({ ok: true });
      }

      return json({ error: `unknown op: ${op}` }, 400);
    } catch (e) {
      return json({ error: e instanceof Error ? e.message : String(e) }, 409);
    }
  }
}
