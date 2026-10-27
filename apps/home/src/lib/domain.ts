// THE single source of demo-sso-next's deployment-domain config (ADR-0021).
// No other file in this app should hardcode a hostname or the name TLD — import
// from here. This module is deployment-specific BY DESIGN and must never be
// hoisted into packages/* (enforced by `pnpm check:no-domain-in-packages`).
//
// SSO/A2A split (spec 232): the human SSO home is `<handle>.impact-agent.me`
// (this app); the agent's A2A endpoint is a separate domain
// `<handle>.impact-agent.io` (the demo-a2a Worker). Names live under a
// permissionless subregistry `<label>.demo.agent`.

import { parseAgentName, parseSubdomainLabel } from '@agenticprimitives/agent-naming';
import { PERMISSIONLESS_SUBREGISTRIES } from './chain';

/** Registrable Connect SSO domain — each person's home is a single-label subdomain. */
export const CONNECT_DOMAIN = process.env.NEXT_PUBLIC_CONNECT_DOMAIN || 'impact-agent.me';
/** Registrable A2A domain (served by demo-a2a, not this app) — for display/links. */
export const A2A_DOMAIN = process.env.NEXT_PUBLIC_A2A_DOMAIN || 'impact-agent.io';
/** The TLD names are claimed under (the `.impact` permissionless subregistry). */
export const AGENT_NAME_PARENT = process.env.NEXT_PUBLIC_AGENT_NAME_PARENT || 'impact';

/** The Agentic Edge origin (spec 288) — the admission Worker that signs the GatewayAssertion demo-a2a
 *  requires on `/mcp/*`. This MUST equal the `next.config` `DEMO_EDGE_URL` default: the browser MCP-data
 *  path (`/a2a/mcp/*` rewrite) and the server-side vault body-store both route THROUGH the edge, so both
 *  fall back to this same origin when `DEMO_EDGE_URL` is unset (the reason the edge "just works" on Vercel
 *  with no per-deploy env var). Override only for an edge-less local dev (`DEMO_EDGE_URL=''`). */
export const DEMO_EDGE_ORIGIN_DEFAULT = process.env.NEXT_PUBLIC_DEMO_EDGE_ORIGIN || 'https://demo-edge-production.richardpedersen3.workers.dev';

/** THIS DEPLOYMENT'S VAULT SERVER ID — the `server` every record-scope grant the Home issues names, and the
 *  `vaultId` a person signs in the vault-key ceremony. The vault (`VAULT_SERVER_ID` on `apps/vault`) and the
 *  runtime hold the SAME value; a second deployment on the same chain (spec 399 — a product repo's own estate)
 *  names its own, so a grant made to one estate's vault never satisfies another's. Unset ⇒ `demo-mcp`, the id
 *  Ring 0's estates were provisioned under. */
export const VAULT_SERVER_ID = process.env.NEXT_PUBLIC_VAULT_SERVER_ID || 'demo-mcp';

/** THE HOME MCP's origin (spec 397) — the Worker Claude.ai connects to as a custom connector, which then puts the
 *  person's question to their own agent under the `ask-as-me` wire. One constant: the whitelabel config registers
 *  `${HOME_MCP_ORIGIN}/oauth/callback` as the `home-mcp` client's redirect URI, and the front door prints
 *  `${HOME_MCP_ORIGIN}/mcp` as the connector URL — a deployment that runs its own Worker sets
 *  `NEXT_PUBLIC_HOME_MCP_ORIGIN` once. Unset ⇒ faithnet's, the estate Ring 0 deploys. */
export const HOME_MCP_ORIGIN = (process.env.NEXT_PUBLIC_HOME_MCP_ORIGIN || 'https://home-mcp.faithnet.io').replace(/\/+$/, '');

/** Alias kept for existing imports. */
export const CENTRAL_AUTH_DOMAIN = CONNECT_DOMAIN;
/** Platform (apex) Connect origin — landing + bootstrap default. */
export const PLATFORM_AUTH_ORIGIN = `https://${CONNECT_DOMAIN}`;

/** The ONE origin this Home is known by to everything outside it.
 *
 *  A Home can be reachable at more than one host — faithnet.me and www.faithnet.me both serve it, with no
 *  redirect between them. Relying apps allowlist exactly one, so which host you happened to be on decided
 *  whether sign-out could come back: field-web accepts a return only from `https://www.faithnet.me`, and a
 *  person signing out from the apex was handed to field-web and left there, signed out, on an app they
 *  were not using.
 *
 *  Unset ⇒ no canonicalisation (today's behaviour). Deployed Homes set it. */
export const HOME_ORIGIN = process.env.NEXT_PUBLIC_HOME_ORIGIN || '';

/** Single-label subdomain of `baseDomain` (alice.impact-agent.me → alice). The
 *  apex, nested labels, `www`, and non-matching hosts → null. */
export function parseAgentSubdomain(hostname: string, baseDomain: string = CONNECT_DOMAIN): string | null {
  return parseSubdomainLabel(hostname, baseDomain, ['www']);
}

/** The handle this page serves on a personal subdomain, else null (apex / pages.dev / localhost). */
export function subdomainHandle(): string | null {
  if (typeof window === 'undefined') return null;
  return parseAgentSubdomain(window.location.hostname);
}

/** Personal SSO origin for a label (alice → https://alice.impact-agent.me). */
export function personalAuthOrigin(label: string): string {
  return `https://${label}.${CONNECT_DOMAIN}`;
}

/** The `.agent` name for a label (alice → alice.demo.agent). */
export function agentNameForLabel(label: string): string {
  return `${label}.${AGENT_NAME_PARENT}`;
}

/**
 * spec 346 migration — the ORDERED set of person roots a bare subdomain label may denote on this deployment
 * (`NEXT_PUBLIC_AGENT_NAME_PARENTS`, e.g. `me,impact` while an estate moves from the legacy root to `.me`).
 * A label denotes at most ONE home: the claim route refuses a label that is taken under any listed root, so
 * resolving the candidates in order is a lookup over one well-defined key, not a fallback between mechanisms.
 * Defaults to just `AGENT_NAME_PARENT`.
 */
export const AGENT_NAME_PARENTS: readonly string[] = (process.env.NEXT_PUBLIC_AGENT_NAME_PARENTS || AGENT_NAME_PARENT)
  .split(',').map((s) => s.trim()).filter(Boolean);

/** The candidate full names a bare label may resolve to, typed-first. */
export function candidateNamesForLabel(label: string): string[] {
  const l = nameLabel(label);
  return AGENT_NAME_PARENTS.map((p) => `${l}.${p}`);
}

/**
 * Typed suffixes the claim flow may offer next to the legacy `AGENT_NAME_PARENT` (spec 346 §4).
 *
 * DERIVED, not declared: a suffix is claimable exactly when this chain has a provisioned root for it —
 * which is what `permissionlessSubregistries` in the deployment JSON records (`AddTypedRoots.s.sol` writes
 * it). A hand-set `NEXT_PUBLIC_CLAIMABLE_TLDS` remains as an override for a deployment that wants to offer
 * fewer, but it can no longer be the reason a provisioned root is invisible: `.svc` existed on chain with a
 * root at `0xeBe1…74A2` and the Home would not offer it, because a separate list had never been updated
 * (2026-09-03 — the same drift as the contracts table, one layer up).
 */
const DECLARED_TLDS: readonly string[] = (process.env.NEXT_PUBLIC_CLAIMABLE_TLDS || '').split(',').map((s) => s.trim()).filter(Boolean);
const PROVISIONED_TLDS: readonly string[] = Object.keys(PERMISSIONLESS_SUBREGISTRIES).filter((t) => !!PERMISSIONLESS_SUBREGISTRIES[t]);
export const CLAIMABLE_TLDS: readonly string[] = DECLARED_TLDS.length ? DECLARED_TLDS.filter((t) => PROVISIONED_TLDS.includes(t)) : PROVISIONED_TLDS;

/** Parse a name with the agent-naming grammar, or null when it is not a typed/legacy name at all. */
function parsedOrNull(name: string) {
  try {
    return parseAgentName(name);
  } catch {
    return null;
  }
}

/** The label of a name (alice.demo.agent → alice; alice → alice; rpedersen.me → rpedersen; vault.svc@x.org → vault). */
export function nameLabel(name: string): string {
  const p = parsedOrNull(name);
  if (p && (p.kind === 'canonical' || p.kind === 'scoped')) return p.handle!.label;
  return (
    name
      .trim()
      .toLowerCase()
      .replace(new RegExp(`\\.${AGENT_NAME_PARENT.replace(/\./g, '\\.')}$`), '')
      .replace(/\.+$/, '')
      .split('.')[0] ?? ''
  );
}

/** A name as the naming service will be asked for it — already-qualified names UNCHANGED.
 *
 *  The two lookup routes each carried `n.endsWith('.impact') ? n : n + '.impact'`, which appended the
 *  legacy parent to any name that did not already end in it. A typed name became `phone-6115.me.impact`,
 *  resolved to nothing, and every typed home reported "No home named …" on its own subdomain and could
 *  not sign in by name (2026-09-01). It also hardcoded the literal parent instead of this deployment's.
 *
 *  The grammar already knows the difference, so ask it: anything `parseAgentName` accepts — canonical
 *  (`x.me`), scoped (`x.svc@y.org`) or legacy (`x.impact`, `x.demo.agent`) — is qualified and is used as
 *  given. Only a BARE label takes this deployment's parent. A dotted string the grammar rejects is
 *  returned untouched: it resolves to nothing, which is the honest answer for a malformed name and
 *  better than inventing a third name out of it.
 */
export function qualifiedAgentName(raw: string): string {
  const n = raw.trim().toLowerCase().replace(/\.+$/, '');
  if (!n) return n;
  const p = parsedOrNull(n);
  if (p) return p.normalized;
  return n.includes('.') ? n : `${n}.${AGENT_NAME_PARENT}`;
}

/** The root a NEW person claim goes under: `.me` once this deployment lists it as claimable, else the legacy parent. */
export const NEW_PERSON_TLD: string = CLAIMABLE_TLDS.includes('me') ? 'me' : AGENT_NAME_PARENT;

/** Normalize any name/label to a full name for a NEW claim: a typed name stays typed (normalized); a legacy
 *  `<label>.<AGENT_NAME_PARENT>` stays as given; a bare label becomes `<label>.<NEW_PERSON_TLD>`. To find the home an
 *  EXISTING label denotes, resolve `candidateNamesForLabel` instead (`resolveHomeNameForLabel` in connect-client). */
export function toAgentName(nameOrLabel: string): string {
  const n = nameOrLabel.trim().toLowerCase();
  const p = parsedOrNull(n);
  if (p && (p.kind === 'canonical' || p.kind === 'scoped')) return p.normalized;
  return n.endsWith(`.${AGENT_NAME_PARENT}`) ? n : `${nameLabel(n)}.${NEW_PERSON_TLD}`;
}

/** The deployment's agent directory (spec 346 §7 registry URN) the Studio lists agents in — e.g.
 *  `urn:ap:registry:faithnet-agents`. Absent ⇒ the directory listing row says the directory is not set up. */
export const AGENT_REGISTRY_URN = process.env.NEXT_PUBLIC_AGENT_REGISTRY_URN || '';

/** The skills registry (skills-a2a) that serves domain archetypes and their compiled definitions.
 *  The Home READS from it — the corpus is where a domain author's SKILL.md contracts live, and reading
 *  them is what makes an edit there change what an agent does here (agent-rules:
 *  one-capability-model-generates-both). Never written to from the Home. */
export const SKILLS_REGISTRY_ORIGIN = skillsRegistryOrigin(process.env.NEXT_PUBLIC_SKILLS_REGISTRY);

/** `off` means this Home uses no skills registry (Global.Church, 2026-10-27: none of its own yet, and it must not
 *  reach another estate's); every reader then skips or says so. Unset keeps the upstream default. */
export function skillsRegistryOrigin(raw: string | undefined): string {
  const v = (raw ?? '').trim();
  if (v.toLowerCase() === 'off') return '';
  return v || 'https://skills-a2a-production.richardpedersen3.workers.dev';
}

/** Which skills CONTEXTS this Home offers archetypes from, in order. `agentic-trust` is the upper (a
 *  treasury is not a domain concept); the white-label domain follows. */
export const SKILLS_CONTEXTS = (process.env.NEXT_PUBLIC_SKILLS_CONTEXTS || 'agentic-trust,faith')
  .split(',').map((s) => s.trim()).filter(Boolean);
