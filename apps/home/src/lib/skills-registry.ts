// THE SKILLS REGISTRY, READ FROM THE HOME — agent-rules/one-capability-model-generates-both.
//
// A domain author writes a SKILL.md execution contract in the skills app and links it to an archetype.
// The registry compiles that into an `AgentHarnessDefinitionV1`. This is how the Home READS those, so a
// contract edited over there changes what an agent does over here — without a deploy, and without the
// capability being written a second time in this repo.
//
// READ-ONLY, and deliberately: the Home never authors a definition (spec 354 — the compiler owns that,
// this repo consumes). What the Home does with one is the K3 ceremony: show the diff, and on approval
// write the assignment to the agent's own vault. A definition is behaviour; it grants nothing.
//
// FAIL-SOFT. An unreachable registry leaves the app-config catalog standing (spec 354 §3 defaults), which
// is why `catalogForKind` remains the floor rather than the fallback-of-last-resort: both are real
// sources and the registry is the one a domain author can change.
import { validateAgentHarnessDefinition, definitionDigest, type AgentHarnessDefinitionV1 } from '@agenticprimitives/capability-claims';
import { SKILLS_REGISTRY_ORIGIN, SKILLS_CONTEXTS } from './domain';

export interface RegistryArchetype {
  key: string;
  label: string;
  summary: string;
  /** The skills context it came from — shown so a steward knows which domain owns the contract. */
  context: string;
  /** Canonical skill ids whose contracts compiled it. Empty means it compiled from built-in fallbacks. */
  skills: string[];
  definition: AgentHarnessDefinitionV1;
  digest: string;
  /** Compiler advisories — chiefly "this capability has no linked SKILL.md contract". Surfaced, because
   *  a steward choosing a playbook should see which parts of it nobody has written a contract for. */
  warnings: string[];
}

interface ArchetypeRow { id: string; label?: string; description?: string; kind?: string; skills?: string[] }

const j = async (r: Response): Promise<unknown> => (r.ok ? r.json().catch(() => null) : null);

/** Every archetype in one context whose compiled definition applies to `agentType`. */
async function fromContext(context: string, agentType: string): Promise<RegistryArchetype[]> {
  if (!SKILLS_REGISTRY_ORIGIN) return [];
  const base = SKILLS_REGISTRY_ORIGIN.replace(/\/$/, '');
  const list = (await j(await fetch(`${base}/context/contexts/${context}/archetypes`))) as { archetypes?: ArchetypeRow[] } | null;
  const rows = list?.archetypes ?? [];
  const out: RegistryArchetype[] = [];
  await Promise.all(rows.map(async (row) => {
    // Cheap pre-filter on the archetype's declared kind; the DEFINITION's applicableAgentTypes is the
    // authority and is checked below, because that is the field run admission checks too.
    if (row.kind && row.kind.toLowerCase() !== agentType) return;
    const d = (await j(await fetch(`${base}/context/contexts/${context}/archetypes/${row.id}/definition`))) as
      { definition?: AgentHarnessDefinitionV1; digest?: string; warnings?: string[] } | null;
    if (!d?.definition) return;
    // A definition this repo cannot validate is one this repo will not offer. The ceremony writes it into
    // an agent's vault, where run admission re-derives its digest — offering an invalid one would produce
    // an assignment the harness then refuses, which reads to a steward as the agent being broken.
    if (!validateAgentHarnessDefinition(d.definition).ok) return;
    if (!d.definition.applicableAgentTypes.includes(agentType)) return;
    out.push({
      key: `${context}:${row.id}`,
      label: row.label || row.id,
      summary: row.description || '',
      context,
      skills: row.skills ?? [],
      definition: d.definition,
      digest: d.digest ?? definitionDigest(d.definition),
      warnings: d.warnings ?? [],
    });
  }));
  return out;
}

/** Archetypes assignable to an agent of this ADR-0061 type, across every configured context. */
export async function registryArchetypesFor(agentType: string | undefined): Promise<RegistryArchetype[]> {
  const t = (agentType ?? '').toLowerCase();
  if (!t) return [];
  const all = await Promise.all(SKILLS_CONTEXTS.map((c) => fromContext(c, t).catch(() => [])));
  return all.flat().sort((a, b) => a.label.localeCompare(b.label));
}
