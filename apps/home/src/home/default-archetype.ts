// THE DEFAULT PLAYBOOK A NEW AGENT IS BORN WITH — spec 354 §3.
//
// Every derived agent type maps to a default archetype (§3), and a person's own agent is the surface the
// Home's Ask runs on. Until this existed, a newly-onboarded person had no playbook at all: every
// capability their agent offered came from hardcoded tool declarations, and the SKILL.md contracts a
// domain author wrote reached them only if someone assigned an archetype by hand.
//
// BEST-EFFORT, ALWAYS. An agent with no assignment runs the bare harness — the documented fallback, not a
// broken state (spec 354 §4.3). So a registry that is unreachable, a definition that will not validate,
// or a grant that does not yet carry the scope all leave onboarding successful and the agent working.
// Failing a person's enrolment because a *behaviour* could not be attached would be the tail wagging the
// dog, and behaviour grants nothing.
import { validateAgentHarnessDefinition, type AgentHarnessDefinitionV1 } from '@agenticprimitives/capability-claims';
import { SKILLS_REGISTRY_ORIGIN } from '../lib/domain';
import { ensureCsrfToken, csrfHeaders } from '../csrf';

/** ADR-0061 type slug → the archetype that type is born with. Product mapping, so it lives in the app.
 *
 *  A TREASURY BORN WITHOUT ONE PAYS SILENTLY. The spec-360 effect resolver reads the PAYER agent's
 *  playbook, so an unassigned treasury promises nothing and tells nobody when its money moves — which is
 *  exactly the incident that started spec 360, reappearing one agent at a time. An org is a payer too.
 *  Every kind that can hold or move value is born knowing what follows the act. */
const DEFAULT_ARCHETYPE: Record<string, { context: string; archetype: string }> = {
  person: { context: 'agentic-trust', archetype: 'person-steward' },
  treasury: { context: 'agentic-trust', archetype: 'treasury-steward' },
  org: { context: 'agentic-trust', archetype: 'org-steward' },
  team: { context: 'agentic-trust', archetype: 'org-steward' },
};

/** The Home's own words for what it just created → the ADR-0061 type slug the registry answers for.
 *  `person-treasury` and `org-treasury` are both a TREASURY; the prefix says whose it is, which is a
 *  fact about the tree and never about the kind of agent. */
export function typeSlugForCreatedKind(kind: string): string {
  const k = (kind ?? '').toLowerCase();
  if (k.endsWith('-treasury') || k === 'treasury') return 'treasury';
  return k;
}

/** The default archetype's CURRENT compiled definition, as the registry serves it now — its id and digest, or null. */
export async function currentDefaultArchetype(kind: string): Promise<{ archetypeId: string; digest: string } | null> {
  const target = DEFAULT_ARCHETYPE[typeSlugForCreatedKind(kind)];
  if (!target || !SKILLS_REGISTRY_ORIGIN) return null;
  try {
    const r = await fetch(`${SKILLS_REGISTRY_ORIGIN.replace(/\/$/, '')}/context/contexts/${target.context}/archetypes/${target.archetype}/definition`);
    if (!r.ok) return null;
    const body = (await r.json()) as { definition?: AgentHarnessDefinitionV1; digest?: string };
    return body.definition?.archetypeId && body.digest ? { archetypeId: body.definition.archetypeId, digest: body.digest } : null;
  } catch { return null; }
}

/**
 * Assign the default archetype for `kind` to a newly created agent. Returns what happened, for the
 * caller's log — never throws.
 */
export async function assignDefaultArchetype(
  agent: string,
  kind: string,
  session: string,
): Promise<{ ok: boolean; reason?: string; archetypeId?: string }> {
  const slug = typeSlugForCreatedKind(kind);
  const target = DEFAULT_ARCHETYPE[slug];
  if (!target) return { ok: false, reason: `no default archetype for ${kind}` };
  if (!SKILLS_REGISTRY_ORIGIN) return { ok: false, reason: 'this Home has no skills registry' };
  try {
    const base = SKILLS_REGISTRY_ORIGIN.replace(/\/$/, '');
    const r = await fetch(`${base}/context/contexts/${target.context}/archetypes/${target.archetype}/definition`);
    if (!r.ok) return { ok: false, reason: `registry ${r.status}` };
    const body = (await r.json()) as { definition?: AgentHarnessDefinitionV1; digest?: string };
    const definition = body.definition;
    if (!definition || !body.digest) return { ok: false, reason: 'no definition' };
    // A definition this Home cannot validate is one it will not write: run admission would refuse the
    // assignment, and the agent would read as broken rather than as unassigned.
    if (!validateAgentHarnessDefinition(definition).ok) return { ok: false, reason: 'definition invalid' };
    if (!definition.applicableAgentTypes.includes(slug)) {
      return { ok: false, reason: `definition does not apply to ${slug}` };
    }
    await ensureCsrfToken();
    const put = await fetch('/connect/channels', {
      method: 'POST',
      credentials: 'include',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${session}`, ...csrfHeaders() },
      body: JSON.stringify({
        action: 'archetypeAssignmentPut',
        communityId: agent.toLowerCase(),
        record: {
          type: 'ap.archetype-assignment.v1',
          archetypeId: definition.archetypeId,
          archetypeVersion: definition.archetypeVersion,
          definitionDigest: body.digest,
          definition,
        },
      }),
    });
    const out = (await put.json().catch(() => ({}))) as { ok?: boolean; error?: string };
    if (!put.ok || out.ok !== true) return { ok: false, reason: out.error ?? `write ${put.status}` };
    return { ok: true, archetypeId: definition.archetypeId };
  } catch (e) {
    return { ok: false, reason: e instanceof Error ? e.message : String(e) };
  }
}
