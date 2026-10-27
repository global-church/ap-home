// A PLAYBOOK COMPOSED FROM A BASE AND THE PACKS OF THE ROLES ITS PERSON HOLDS — spec 427 §5.
//
// An agent runs ONE definition. What a person does differs by where they belong, so their playbook is their BASE
// (the default for their agent type, or whatever they chose) plus one PACK per role they have chosen to equip. The
// skills registry composes it from compiled, digest-pinned parts; this module asks for the composition, checks it,
// and writes the same `archetype.assignment` record the Playbook page has always written, with `composedFrom`
// saying which part came from which membership.
//
// WHO DECIDES WHAT (§2 D4, and the reason this file is careful):
//   · an ORGANIZATION names a role and offers a pack. It cannot write anybody's playbook, and nothing here lets it.
//   · the PERSON equips — one press, their own session, their own vault. Nothing is ever ADDED without that press.
//   · a pack whose membership ENDED, or whose role no longer offers it, is DROPPED when their Home reconciles —
//     a role they no longer hold should not keep shaping what their agent does. Dropping needs no press, but it
//     needs an ANSWER: an organization that could not be asked leaves its pack exactly where it is.
//
// The roles are read by an INTENT, not a route: the person's own agent is asked `person.roles.list` with a supplied
// plan (each organization answers for its own record of them). A pure planner decides; the fetchers only carry.
import { validateAgentHarnessDefinition, definitionDigest, type AgentHarnessDefinitionV1 } from '@agenticprimitives/capability-claims';
import { SKILLS_REGISTRY_ORIGIN, SKILLS_CONTEXTS } from '../lib/domain';
import { ensureCsrfToken, csrfHeaders } from '../csrf';

export interface PackRef { context: string; archetype: string; version?: string }

/** One pack in a composed playbook, with the membership it came from and who pressed. */
export interface ComposedPack {
  context: string; archetype: string; version: string; digest: string;
  organization: string; organizationName?: string;
  roleDefinitionId: string; roleName: string;
  equippedAt: string; equippedBy: string; equippedAs: 'self' | 'steward';
}
export interface ComposedFrom {
  base: { context: string; archetype: string; version: string; digest: string };
  packs: ComposedPack[];
}

/** The record in the agent's vault (`archetype.assignment`). The runtime reads `definition` + `definitionDigest`. */
export interface ComposedAssignmentRecord {
  type: 'ap.archetype-assignment.v1';
  archetypeId: string; archetypeVersion: string; definitionDigest: string;
  definition: AgentHarnessDefinitionV1;
  composedFrom?: ComposedFrom;
}

/** A role one organization records the person as (`person.roles.list`). */
export interface HeldRole {
  org: string; name: string | null; askedOf?: string;
  assignedRole: string; roleName?: string; roleDefinitionId?: string; description?: string;
  scope?: 'organization' | 'team'; accessRole?: string;
  skillPackRefs: PackRef[];
  ended: boolean;
}
export interface RolesRead { roles: HeldRole[]; asked: string[]; unread: string[] }

const packKey = (p: PackRef): string => `${p.context}/${p.archetype}`;
const lower = (s: string | undefined | null): string => String(s ?? '').toLowerCase();

// ── THE PLAN (pure) ─────────────────────────────────────────────────────────────────────────────────────────────

export interface EquippedPackState {
  pack: ComposedPack;
  /** `held` — the role still offers it; `ended` — the membership ended; `changed` — the role no longer offers this
   *  pack (a steward changed the role); `unknown` — the organization could not be asked, so nothing is decided. */
  state: 'held' | 'ended' | 'changed' | 'unknown';
}
export interface PackOffer { role: HeldRole; pack: PackRef }
export interface RolePackPlan {
  equipped: EquippedPackState[];
  /** Packs a held role offers that are not equipped — shown, never applied without the person's press. */
  offers: PackOffer[];
  /** Equipped packs to drop when reconciling: the organization ANSWERED and no longer supports them. */
  drop: ComposedPack[];
}

/**
 * What the playbook holds against what the person's memberships say it should. Pure.
 * A pack is tied to (organization, pack reference). It stays `held` while a LIVE role at that organization offers
 * that reference. Anything the organization did not answer about is `unknown` and is never dropped.
 */
export function planRolePacks(composedFrom: ComposedFrom | undefined | null, read: RolesRead | null): RolePackPlan {
  const packs = composedFrom?.packs ?? [];
  const answered = new Set((read?.asked ?? []).map(lower).filter((o) => !(read?.unread ?? []).map(lower).includes(o)));
  const byOrg = new Map<string, HeldRole>();
  for (const r of read?.roles ?? []) byOrg.set(lower(r.org), r);
  const equipped: EquippedPackState[] = packs.map((pack) => {
    const org = lower(pack.organization);
    const role = byOrg.get(org);
    if (!read || (!role && !answered.has(org))) return { pack, state: 'unknown' as const };
    if (!role || role.ended) return { pack, state: 'ended' as const }; // answered, and records no live membership
    return { pack, state: role.skillPackRefs.some((p) => packKey(p) === packKey(pack)) ? 'held' as const : 'changed' as const };
  });
  const have = new Set(packs.map((p) => `${lower(p.organization)}|${packKey(p)}`));
  const offers: PackOffer[] = [];
  for (const role of read?.roles ?? []) {
    if (role.ended) continue;
    for (const pack of role.skillPackRefs) if (!have.has(`${lower(role.org)}|${packKey(pack)}`)) offers.push({ role, pack });
  }
  return { equipped, offers, drop: equipped.filter((e) => e.state === 'ended' || e.state === 'changed').map((e) => e.pack) };
}

/** The heading a pack's instructions sit under in the composed playbook: "Team lead at Weld Corridor Team". */
export const packHeading = (p: Pick<ComposedPack, 'roleName' | 'organizationName' | 'organization'>): string =>
  `${p.roleName} at ${p.organizationName?.trim() || `${p.organization.slice(0, 6)}…${p.organization.slice(-4)}`}`;

// ── THE READ (an intent) ────────────────────────────────────────────────────────────────────────────────────────

/**
 * Ask the person's OWN agent what roles they hold (`person.roles.list`, a supplied plan — no model, no run in the
 * human list). `alsoAsk` names organizations to ask even if the person's links no longer list them: the ones an
 * equipped pack came from, so a membership that ended AND was unlinked is still answered rather than left unknown.
 * Null when the agent could not be asked or its playbook does not offer the read yet.
 */
export async function readMyRoles(token: string, person: string, alsoAsk: readonly string[] = []): Promise<RolesRead | null> {
  await ensureCsrfToken();
  const steps = [{ toolId: 'person.roles.list', args: {} as Record<string, unknown> }, ...[...new Set(alsoAsk.map(lower))].filter((o) => /^0x[0-9a-f]{40}$/.test(o)).map((org) => ({ toolId: 'person.roles.list', args: { org } as Record<string, unknown> }))];
  const r = await fetch('/a2a/harness/ask', {
    method: 'POST', credentials: 'include', headers: { 'content-type': 'application/json', ...csrfHeaders() },
    body: JSON.stringify({ session: token, addressee: person.toLowerCase(), message: 'what roles do i hold', background: true, rowsOnly: true, plan: { steps } }),
  }).catch(() => null);
  const out = r ? ((await r.json().catch(() => ({}))) as { reply?: { kind?: string; results?: Array<{ toolId: string; result: unknown }> } }) : {};
  if (out.reply?.kind !== 'answer') return null;
  const results = (out.reply.results ?? []).filter((x) => x.toolId === 'person.roles.list').map((x) => x.result as { roles?: HeldRole[]; asked?: string[]; unread?: string[]; refused?: string });
  if (!results.length || results.every((x) => x.refused)) return null;
  return mergeRolesReads(results);
}

/** Several answers about the same person, as one: a role per organization (a later, narrower ask wins), and an
 *  organization is `unread` only when NO ask reached it. Pure. */
export function mergeRolesReads(results: ReadonlyArray<{ roles?: HeldRole[]; asked?: string[]; unread?: string[] }>): RolesRead {
  const roles = new Map<string, HeldRole>();
  const asked = new Set<string>(); const unread = new Set<string>(); const reached = new Set<string>();
  for (const res of results) {
    const bad = new Set((res.unread ?? []).map(lower));
    for (const o of res.asked ?? []) { asked.add(lower(o)); if (!bad.has(lower(o))) reached.add(lower(o)); }
    for (const o of bad) unread.add(o);
    for (const role of res.roles ?? []) roles.set(lower(role.org), { ...role, org: lower(role.org), skillPackRefs: role.skillPackRefs ?? [] });
  }
  return { roles: [...roles.values()], asked: [...asked], unread: [...unread].filter((o) => !reached.has(o)) };
}

// ── THE COMPOSITION (the registry's) ────────────────────────────────────────────────────────────────────────────

export interface Composition { definition: AgentHarnessDefinitionV1; digest: string; parts: Array<{ ref: string; digest: string; archetypeId: string; version: string }>; warnings: string[] }

/** Ask the registry to compose `base` + `packs`, and refuse anything this Home would not write: a definition that
 *  does not validate, or whose digest is not its own. A composition is whole or it is an error. */
export async function composePlaybook(base: PackRef, packs: ReadonlyArray<PackRef & { as?: string }>): Promise<Composition> {
  if (!SKILLS_REGISTRY_ORIGIN) throw new Error('this Home has no skills registry to compose a playbook from');
  const r = await fetch(`${SKILLS_REGISTRY_ORIGIN.replace(/\/$/, '')}/context/compose`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ base: { context: base.context, archetype: base.archetype }, packs: packs.map((p) => ({ context: p.context, archetype: p.archetype, ...(p.as ? { as: p.as } : {}) })) }),
  });
  const body = (await r.json().catch(() => ({}))) as Partial<Composition> & { error?: string };
  if (!r.ok || !body.definition || !body.digest) throw new Error(body.error ?? `the registry could not compose this playbook (${r.status})`);
  const check = validateAgentHarnessDefinition(body.definition);
  if (!check.ok) throw new Error(`the composed playbook is not a valid definition: ${check.errors[0]}`);
  if (definitionDigest(body.definition) !== body.digest) throw new Error('the composed playbook does not hash to the digest the registry gave — not written');
  return { definition: body.definition, digest: body.digest, parts: body.parts ?? [], warnings: body.warnings ?? [] };
}

/** One part as the registry compiles it NOW — its digest and the tools it carries. Null when it is not served. */
export async function currentPart(ref: PackRef): Promise<{ digest: string; archetypeId: string; version: string; tools: string[] } | null> {
  if (!SKILLS_REGISTRY_ORIGIN) return null;
  try {
    const r = await fetch(`${SKILLS_REGISTRY_ORIGIN.replace(/\/$/, '')}/context/contexts/${ref.context}/archetypes/${ref.archetype}/definition`);
    if (!r.ok) return null;
    const b = (await r.json()) as { definition?: AgentHarnessDefinitionV1; digest?: string };
    return b.definition && b.digest ? { digest: b.digest, archetypeId: b.definition.archetypeId, version: b.definition.archetypeVersion, tools: (b.definition.tools ?? []).map((t) => t.id) } : null;
  } catch { return null; }
}

/** ADR-0061 type slug → the estate's default base (mirrors `default-archetype.ts`; a person's is what matters here). */
const DEFAULT_BASE: Record<string, PackRef> = {
  person: { context: 'agentic-trust', archetype: 'person-steward' },
  org: { context: 'agentic-trust', archetype: 'org-steward' },
  team: { context: 'agentic-trust', archetype: 'org-steward' },
  treasury: { context: 'agentic-trust', archetype: 'treasury-steward' },
};

/**
 * WHICH REGISTRY ARCHETYPE IS THIS PLAYBOOK'S BASE? A composition names it. A playbook with no `composedFrom` (the
 * default, or one picked by hand) is the base of its FIRST composition, kept BY REFERENCE: found among the default
 * for the agent's type and the contexts this Home browses, by its archetype id. One the registry does not serve
 * (edited by hand, or from a context this Home does not read) is refused with the reason — equipping must never
 * silently replace a playbook somebody made.
 */
export async function resolveBase(current: ComposedAssignmentRecord | null, typeSlug: string): Promise<{ ok: true; base: PackRef } | { ok: false; reason: string }> {
  if (current?.composedFrom?.base) return { ok: true, base: { context: current.composedFrom.base.context, archetype: current.composedFrom.base.archetype } };
  const fallback = DEFAULT_BASE[typeSlug];
  if (!current) return fallback ? { ok: true, base: fallback } : { ok: false, reason: `there is no default playbook for a ${typeSlug} agent to build on` };
  const candidates: PackRef[] = [];
  if (fallback) candidates.push(fallback);
  if (!SKILLS_REGISTRY_ORIGIN) return { ok: false, reason: 'this Home has no skills registry' };
  const base = SKILLS_REGISTRY_ORIGIN.replace(/\/$/, '');
  for (const context of SKILLS_CONTEXTS) {
    const list = (await fetch(`${base}/context/contexts/${context}/archetypes`).then((r) => (r.ok ? r.json() : null)).catch(() => null)) as { archetypes?: Array<{ id: string }> } | null;
    for (const row of list?.archetypes ?? []) if (!candidates.some((c) => c.context === context && c.archetype === row.id)) candidates.push({ context, archetype: row.id });
  }
  // The archetype id ends in the registry id (`skill:archetypes/person-steward`): try the likely ones first.
  const tail = current.archetypeId.split('/').pop() ?? '';
  candidates.sort((a, b) => Number(b.archetype === tail) - Number(a.archetype === tail));
  for (const c of candidates) {
    if (c.archetype !== tail) break; // only same-named archetypes can carry this id
    const now = await currentPart(c);
    if (now?.archetypeId === current.archetypeId) return { ok: true, base: c };
  }
  return { ok: false, reason: `this agent's playbook (${current.archetypeId.replace(/^skill:[^/]+\//, '')}) is not one the skills registry serves here, so a role pack cannot be added to it. Switch to a registry playbook first, then equip the role.` };
}

// ── THE WRITE ───────────────────────────────────────────────────────────────────────────────────────────────────

async function readAssignmentRecord(token: string, agent: string): Promise<ComposedAssignmentRecord | null> {
  const r = await fetch('/connect/channels', { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` }, body: JSON.stringify({ action: 'archetypeAssignmentGet', communityId: agent.toLowerCase() }) });
  const b = (await r.json().catch(() => ({}))) as { ok?: boolean; record?: ComposedAssignmentRecord | null; error?: string };
  if (!r.ok || b.ok !== true) throw new Error(b.error ?? `could not read the playbook (${r.status})`);
  return b.record ?? null;
}

async function writeAssignmentRecord(token: string, agent: string, record: ComposedAssignmentRecord): Promise<void> {
  const r = await fetch('/connect/channels', { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` }, body: JSON.stringify({ action: 'archetypeAssignmentPut', communityId: agent.toLowerCase(), record }) });
  const b = (await r.json().catch(() => ({}))) as { ok?: boolean; error?: string };
  if (!r.ok || b.ok !== true) throw new Error(b.error ?? `the playbook was not written (${r.status})`);
}

export interface PackToEquip { role: HeldRole; pack: PackRef }
export interface RecomposeInput {
  agent: string; token: string; typeSlug: string;
  /** Who is pressing — the session's own agent. `self` when it IS `agent`, else a steward equipping an agent they custody. */
  actor: string;
  add?: readonly PackToEquip[];
  /** Rebuild on a DIFFERENT base (the person switched playbook): the packs they equipped come along. */
  base?: PackRef;
  /** Packs to remove, by (organization, pack reference). */
  remove?: ReadonlyArray<Pick<ComposedPack, 'organization' | 'context' | 'archetype'>>;
  now?: () => string;
}
export interface RecomposeResult { record: ComposedAssignmentRecord; added: string[]; removed: string[]; toolsAdded: string[]; toolsRemoved: string[]; baseMoved: boolean; warnings: string[] }

/**
 * Recompose the agent's playbook: the same base, the packs it holds minus `remove` plus `add`, each compiled as the
 * registry serves it NOW (so a recomposition also takes a newer base or pack — said in `baseMoved` and by the tools
 * that changed). One read, one composition, one write under the existing gate (the agent itself, or its steward).
 * With no pack left the record is the plain base again, and `composedFrom` records that it was composed of nothing.
 */
export async function recomposePlaybook(input: RecomposeInput): Promise<RecomposeResult> {
  const now = (input.now ?? (() => new Date().toISOString()))();
  const current = await readAssignmentRecord(input.token, input.agent);
  const baseRes = input.base ? { ok: true as const, base: input.base } : await resolveBase(current, input.typeSlug);
  if (!baseRes.ok) throw new Error(baseRes.reason);
  const removing = new Set((input.remove ?? []).map((p) => `${lower(p.organization)}|${packKey(p)}`));
  const kept = (current?.composedFrom?.packs ?? []).filter((p) => !removing.has(`${lower(p.organization)}|${packKey(p)}`));
  const adding = (input.add ?? []).filter((a) => !kept.some((p) => lower(p.organization) === lower(a.role.org) && packKey(p) === packKey(a.pack)));
  const equippedAs: 'self' | 'steward' = lower(input.actor) === lower(input.agent) ? 'self' : 'steward';
  const next: Array<Omit<ComposedPack, 'version' | 'digest'>> = [
    ...kept.map(({ version: _v, digest: _d, ...rest }) => rest),
    ...adding.map((a) => ({
      context: a.pack.context, archetype: a.pack.archetype,
      organization: lower(a.role.org), ...(a.role.name ? { organizationName: a.role.name } : {}),
      roleDefinitionId: a.role.roleDefinitionId ?? '', roleName: a.role.roleName ?? a.role.assignedRole,
      equippedAt: now, equippedBy: lower(input.actor), equippedAs,
    })),
  ];
  const composed = await composePlaybook(baseRes.base, next.map((p) => ({ context: p.context, archetype: p.archetype, as: packHeading(p) })));
  if (!composed.definition.applicableAgentTypes.includes(input.typeSlug)) throw new Error(`the composed playbook does not apply to a ${input.typeSlug} agent`);
  const part = (ref: PackRef) => composed.parts.find((x) => x.ref === packKey(ref));
  const basePart = part(baseRes.base);
  if (!basePart) throw new Error('the registry did not report the base part of the composition — not written');
  const packs: ComposedPack[] = next.map((p) => {
    const got = part(p);
    if (!got) throw new Error(`the registry did not report the ${packKey(p)} part of the composition — not written`);
    return { ...p, version: got.version, digest: got.digest };
  });
  const record: ComposedAssignmentRecord = {
    type: 'ap.archetype-assignment.v1',
    archetypeId: composed.definition.archetypeId, archetypeVersion: composed.definition.archetypeVersion,
    definitionDigest: composed.digest, definition: composed.definition,
    composedFrom: { base: { context: baseRes.base.context, archetype: baseRes.base.archetype, version: basePart.version, digest: basePart.digest }, packs },
  };
  await writeAssignmentRecord(input.token, input.agent, record);
  const before = new Set((current?.definition?.tools ?? []).map((t) => t.id));
  const after = new Set(composed.definition.tools.map((t) => t.id));
  return {
    record,
    added: adding.map((a) => packKey(a.pack)),
    removed: (current?.composedFrom?.packs ?? []).filter((p) => removing.has(`${lower(p.organization)}|${packKey(p)}`)).map(packKey),
    toolsAdded: [...after].filter((t) => !before.has(t)),
    toolsRemoved: [...before].filter((t) => !after.has(t)),
    baseMoved: !!current?.composedFrom && current.composedFrom.base.digest !== basePart.digest,
    warnings: composed.warnings,
  };
}

/**
 * RECONCILE (§5.3) — run by the person's own Home when it opens on their own agent. Reads their roles (asking the
 * organizations their packs came from as well), and when a pack's membership has ENDED or its role no longer offers
 * it, recomposes without it. Adds nothing. Does nothing at all for a playbook that was never composed, or when no
 * organization that matters answered. Returns what it dropped, for the caller to say.
 */
export async function reconcileRolePacks(input: { agent: string; token: string; typeSlug: string; record: ComposedAssignmentRecord | null }): Promise<{ dropped: ComposedPack[]; plan: RolePackPlan | null }> {
  const composedFrom = input.record?.composedFrom;
  if (!composedFrom?.packs.length) return { dropped: [], plan: null };
  const read = await readMyRoles(input.token, input.agent, composedFrom.packs.map((p) => p.organization));
  const plan = planRolePacks(composedFrom, read);
  if (!plan.drop.length) return { dropped: [], plan };
  await recomposePlaybook({ agent: input.agent, token: input.token, typeSlug: input.typeSlug, actor: input.agent, remove: plan.drop });
  return { dropped: plan.drop, plan };
}
