// THE ADMIN TAB'S NUMBERS (Global.Church, 2026-10-09) — pure, so the counting rules live next to their tests.
//
// Who is an admin is a deployment fact (`HOME_ADMINS`, a comma list of person addresses), decided by the server on
// every call. An empty list is nobody: there is no fallback admin (ADR-0013).
//
// A GCID account is a distinct person agent behind a LIVE login facet (`facet:email|phone|oidc|cred:*`, the index
// kv-indexer.ts writes). Facets carry no timestamps, so growth comes from a daily snapshot the server keeps from the
// first time the tab is opened; before then the page says "tracking since", never an invented number.
import type { EvidenceLink } from '@agenticprimitives/identity-directory';
import { liveLinks } from './kv-indexer';

const ADDRESS = /^0x[0-9a-f]{40}$/;

/** `HOME_ADMINS` → the set of admin addresses (lower-cased). Anything that is not an address is ignored. */
export function parseAdmins(raw: string | undefined): Set<string> {
  return new Set(
    (raw ?? '')
      .split(',')
      .map((s) => s.trim().toLowerCase())
      .filter((s) => ADDRESS.test(s)),
  );
}

/** The person address at the end of a session `sub` (`eip155:<chain>:0x…` or a bare address). */
export function subjectAddress(sub: string): string | null {
  return sub.match(/0x[0-9a-fA-F]{40}$/)?.[0]?.toLowerCase() ?? null;
}

export function isAdmin(sub: string, admins: Set<string>): boolean {
  const a = subjectAddress(sub);
  return !!a && admins.has(a);
}

export type SignInMethod = 'email' | 'phone' | 'google' | 'passkey' | 'other';

/** Which sign-in method a facet key stands for. */
export function methodOf(key: string): SignInMethod {
  if (key.startsWith('facet:email:')) return 'email';
  if (key.startsWith('facet:phone:')) return 'phone';
  if (key.startsWith('facet:oidc:')) return key.includes('accounts.google.com') ? 'google' : 'other';
  if (key.startsWith('facet:cred:')) {
    const kind = key.slice('facet:cred:'.length).split(':')[0] ?? '';
    return kind === 'passkey' || kind === 'webauthn' ? 'passkey' : kind === 'email' ? 'email' : kind === 'phone' ? 'phone' : 'other';
  }
  return 'other';
}

/** The facet prefixes the count reads. */
export const FACET_PREFIXES = ['facet:email:', 'facet:phone:', 'facet:oidc:', 'facet:cred:'] as const;

function parseLinks(raw: string | null): EvidenceLink[] {
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw) as EvidenceLink | EvidenceLink[];
    if (Array.isArray(parsed)) return parsed;
    return parsed && typeof parsed === 'object' && 'agent' in parsed ? [parsed] : [];
  } catch {
    return [];
  }
}

export interface AccountCounts {
  /** Distinct person agents with at least one live sign-in. A person with two methods counts once. */
  accounts: number;
  /** People per method — one person may appear under several, so these do not add up to `accounts`. */
  byMethod: Record<SignInMethod, number>;
  /** Test identities (test-identity.ts) seen behind a live sign-in, and left out of every number above. */
  testAccounts: number;
}

/** The address at the end of an agent id, or the id itself (lower case) when it has none. */
const addressOf = (agent: string): string => subjectAddress(agent) ?? agent.toLowerCase();

export function countAccounts(facets: { key: string; value: string | null }[], testPeople: ReadonlySet<string> = new Set()): AccountCounts {
  const all = new Set<string>();
  const tests = new Set<string>();
  const per: Record<SignInMethod, Set<string>> = { email: new Set(), phone: new Set(), google: new Set(), passkey: new Set(), other: new Set() };
  for (const f of facets) {
    const m = methodOf(f.key);
    for (const l of liveLinks(parseLinks(f.value))) {
      const a = String(l.agent).toLowerCase();
      if (testPeople.has(addressOf(a))) {
        tests.add(a);
        continue;
      }
      all.add(a);
      per[m].add(a);
    }
  }
  return {
    accounts: all.size,
    byMethod: { email: per.email.size, phone: per.phone.size, google: per.google.size, passkey: per.passkey.size, other: per.other.size },
    testAccounts: tests.size,
  };
}

/** One GCID account for Admin → All accounts (2026-10-26): every person behind a live sign-in, with how they sign in.
 *  The same people `countAccounts` counts, so the list and the Overview number agree. Test identities are flagged,
 *  not dropped, so the page can show or hide them. */
export interface AccountRow { account: string; methods: SignInMethod[]; test: boolean }

export function listAccounts(facets: { key: string; value: string | null }[], testPeople: ReadonlySet<string> = new Set()): AccountRow[] {
  const by = new Map<string, Set<SignInMethod>>();
  for (const f of facets) {
    const m = methodOf(f.key);
    for (const l of liveLinks(parseLinks(f.value))) {
      const a = addressOf(String(l.agent));
      if (!ADDRESS.test(a)) continue;
      (by.get(a) ?? by.set(a, new Set()).get(a)!).add(m);
    }
  }
  return [...by.entries()]
    .map(([account, ms]) => ({ account, methods: [...ms].sort(), test: testPeople.has(account) }))
    .sort((x, y) => x.account.localeCompare(y.account));
}

export interface OrgCounts {
  /** Distinct organizations (every kind but a workspace). */
  organizations: number;
  workspaces: number;
  /** Organizations first linked in the last 7 / 30 days (the link's `createdAt`). */
  newOrganizations7d: number;
  newOrganizations30d: number;
}

const DAY = 24 * 60 * 60 * 1000;

/** `related:<person>:<org>` links → distinct orgs. A person's own other names (kind `person`, relationship `self`)
 *  are people, not organizations, and are left out. */
export function countOrgs(links: { key: string; value: string | null }[], now: number, testPeople: ReadonlySet<string> = new Set()): OrgCounts {
  const first = new Map<string, { kind: string; at: number }>();
  for (const l of links) {
    const org = l.key.split(':')[2]?.toLowerCase();
    if (!org || !ADDRESS.test(org)) continue;
    // A test identity's link does not make an organization real: an org only test people link to is not counted.
    const person = l.key.split(':')[1]?.toLowerCase() ?? '';
    if (testPeople.has(person)) continue;
    let v: { kind?: string; relationship?: string; status?: string; createdAt?: number } = {};
    try {
      v = JSON.parse(l.value ?? '{}') as typeof v;
    } catch {
      /* an unreadable link still names an org */
    }
    if ((v.kind ?? '').toLowerCase() === 'person' || (v.relationship ?? '').toLowerCase() === 'self') continue;
    if (v.status === 'deleted') continue;
    const at = typeof v.createdAt === 'number' ? v.createdAt : Number.POSITIVE_INFINITY;
    const seen = first.get(org);
    if (!seen || at < seen.at) first.set(org, { kind: (v.kind ?? seen?.kind ?? 'org').toLowerCase(), at });
  }
  let organizations = 0, workspaces = 0, n7 = 0, n30 = 0;
  for (const { kind, at } of first.values()) {
    if (kind === 'workspace') { workspaces++; continue; }
    organizations++;
    if (at >= now - 7 * DAY) n7++;
    if (at >= now - 30 * DAY) n30++;
  }
  return { organizations, workspaces, newOrganizations7d: n7, newOrganizations30d: n30 };
}

export interface Snapshot { date: string; accounts: number; organizations: number }

export const dayOf = (t: number): string => new Date(t).toISOString().slice(0, 10);

/** Add today's snapshot (replacing an earlier one for the same day) and keep the newest `keep`. */
export function recordSnapshot(history: Snapshot[], today: Snapshot, keep = 400): Snapshot[] {
  const rest = history.filter((s) => s.date !== today.date);
  return [...rest, today].sort((a, b) => a.date.localeCompare(b.date)).slice(-keep);
}

/** Growth over `days`: today's figure minus the snapshot from that many days ago, or null when the history does
 *  not reach back that far yet (the page then says "tracking since"). */
export function growth(history: Snapshot[], now: number, days: number, field: 'accounts' | 'organizations'): number | null {
  const today = history.find((s) => s.date === dayOf(now));
  const then = history.filter((s) => s.date <= dayOf(now - days * DAY)).pop();
  if (!today || !then) return null;
  return today[field] - then[field];
}

// ── Organization types (Global.Church, 2026-10-21) ──────────────────────────────────────────────────────────────
// The type each organization was given when it was created (lib/org-type.ts), counted from the `orgType` the
// related link carries. "Other" answers are listed in the person's own words: they are how the team finds the
// categories the ontology is missing. Same rules as countOrgs: test people, a person's own names, deleted
// organizations and workspaces are left out.

export interface OrgTypeTally {
  /** Listed types, most used first. */
  byType: { label: string; iri: string; count: number }[];
  /** Organizations whose answer was Other, newest first. */
  other: { text: string; at: number | null }[];
  /** Organizations with no type: created before the question was asked, or outside an app that asks it. */
  noType: number;
}

export function tallyOrgTypes(links: { key: string; value: string | null }[], testPeople: ReadonlySet<string> = new Set()): OrgTypeTally {
  type Seen = { kind: string; at: number; type: { iri: string | null; label?: string; other?: string } | null };
  const orgs = new Map<string, Seen>();
  for (const l of links) {
    const [, personRaw, orgRaw] = l.key.split(':');
    const org = orgRaw?.toLowerCase();
    if (!org || !ADDRESS.test(org) || testPeople.has(personRaw?.toLowerCase() ?? '')) continue;
    let v: { kind?: string; relationship?: string; status?: string; createdAt?: number; orgType?: { iri?: unknown; label?: unknown; other?: unknown } } = {};
    try {
      v = JSON.parse(l.value ?? '{}') as typeof v;
    } catch {
      continue;
    }
    if ((v.kind ?? '').toLowerCase() === 'person' || (v.relationship ?? '').toLowerCase() === 'self' || v.status === 'deleted') continue;
    const t = v.orgType;
    const type =
      t && typeof t === 'object'
        ? typeof t.iri === 'string' && typeof t.label === 'string'
          ? { iri: t.iri, label: t.label }
          : t.iri === null && typeof t.other === 'string'
            ? { iri: null, other: t.other }
            : null
        : null;
    const at = typeof v.createdAt === 'number' ? v.createdAt : Number.POSITIVE_INFINITY;
    const seen = orgs.get(org);
    // Any steward's link that carries the type answers for the organization; the earliest link dates it.
    orgs.set(org, {
      kind: (seen?.kind ?? v.kind ?? 'org').toLowerCase(),
      at: Math.min(seen?.at ?? Number.POSITIVE_INFINITY, at),
      type: seen?.type ?? type,
    });
  }
  const counts = new Map<string, { label: string; iri: string; count: number }>();
  const other: { text: string; at: number | null }[] = [];
  let noType = 0;
  for (const o of orgs.values()) {
    if (o.kind === 'workspace') continue;
    if (!o.type) { noType++; continue; }
    if (o.type.iri === null) { other.push({ text: o.type.other ?? '', at: Number.isFinite(o.at) ? o.at : null }); continue; }
    const c = counts.get(o.type.iri) ?? { label: o.type.label ?? o.type.iri, iri: o.type.iri, count: 0 };
    c.count++;
    counts.set(o.type.iri, c);
  }
  return {
    byType: [...counts.values()].sort((a, b) => b.count - a.count || a.label.localeCompare(b.label)),
    other: other.sort((a, b) => (b.at ?? 0) - (a.at ?? 0)),
    noType,
  };
}

// ── Organizations by app (2026-10-22) ────────────────────────────────────────────────────────────────────────────
// Admin's Organizations tab: every organization an app (an OIDC client, e.g. Gather's `gather-app`) brought to this
// Home, with its name, type and the people who manage it. Built from the related links alone:
//  - an organization belongs to the app when a link to it was granted to that client (`requestedBy`), or when a
//    workspace the app created is governed by it (a host who picked an organization they already had);
//  - its managers are the links to it that are not memberships (`relationship: 'member'`), a person's own names,
//    or the organization itself. Members are counted, never listed;
//  - deleted organizations and workspaces are left out; an organization only test people manage is marked `test`.

export interface AppOrgType { iri: string | null; label?: string; other?: string }

export interface AppOrg {
  org: string;
  /** The display name the person typed ("Richmond Gather"), or the handle when none was given. */
  name: string;
  /** The organization's handle (richmond-gather.org), when it differs from the name. */
  handle: string;
  createdAt: number | null;
  type: AppOrgType | null;
  /** Person addresses that manage it, earliest link first. */
  stewards: string[];
  members: number;
  test: boolean;
}

type LinkValue = {
  orgName?: string; displayName?: string; kind?: string; relationship?: string; status?: string; createdAt?: number;
  requestedBy?: string; governor?: string; orgType?: { iri?: unknown; label?: unknown; other?: unknown };
};

function readType(t: LinkValue['orgType']): AppOrgType | null {
  if (!t || typeof t !== 'object') return null;
  if (typeof t.iri === 'string' && typeof t.label === 'string') return { iri: t.iri, label: t.label };
  if (t.iri === null && typeof t.other === 'string') return { iri: null, other: t.other };
  return null;
}

export function listAppOrganizations(
  links: { key: string; value: string | null }[],
  app: string,
  testPeople: ReadonlySet<string> = new Set(),
): AppOrg[] {
  const parsed: { person: string; org: string; v: LinkValue }[] = [];
  for (const l of links) {
    const [, personRaw, orgRaw] = l.key.split(':');
    const person = personRaw?.toLowerCase() ?? '';
    const org = orgRaw?.toLowerCase() ?? '';
    if (!ADDRESS.test(org)) continue;
    try {
      parsed.push({ person, org, v: JSON.parse(l.value ?? '{}') as LinkValue });
    } catch {
      /* unreadable link: skipped */
    }
  }
  // Which organizations the app brought here.
  const ours = new Set<string>();
  for (const { org, v } of parsed) {
    if (v.requestedBy !== app) continue;
    const kind = (v.kind ?? 'org').toLowerCase();
    if (kind === 'workspace') {
      const g = (v.governor ?? '').toLowerCase();
      if (ADDRESS.test(g)) ours.add(g);
    } else if (kind !== 'person') ours.add(org);
  }
  const byOrg = new Map<string, AppOrg & { deleted: boolean; workspace: boolean; firstAt: Map<string, number> }>();
  for (const { person, org, v } of parsed) {
    if (!ours.has(org)) continue;
    const rel = (v.relationship ?? '').toLowerCase();
    const kind = (v.kind ?? 'org').toLowerCase();
    if (kind === 'person' || rel === 'self') continue;
    const o = byOrg.get(org) ?? { org, name: '', handle: '', createdAt: null, type: null, stewards: [], members: 0, test: false, deleted: false, workspace: false, firstAt: new Map() };
    const at = typeof v.createdAt === 'number' ? v.createdAt : null;
    if (at !== null && (o.createdAt === null || at < o.createdAt)) o.createdAt = at;
    if (!o.handle && v.orgName && v.orgName.toLowerCase() !== org) o.handle = v.orgName;
    if (!o.name && v.displayName) o.name = v.displayName;
    o.type ??= readType(v.orgType);
    if (v.status === 'deleted') o.deleted = true;
    if (kind === 'workspace') o.workspace = true;
    if (rel === 'member') o.members++;
    else if (ADDRESS.test(person) && person !== org && !o.firstAt.has(person)) o.firstAt.set(person, at ?? Number.POSITIVE_INFINITY);
    byOrg.set(org, o);
  }
  const out: AppOrg[] = [];
  for (const o of byOrg.values()) {
    if (o.deleted || o.workspace) continue;
    const stewards = [...o.firstAt.entries()].sort((a, b) => a[1] - b[1]).map(([p]) => p);
    out.push({
      org: o.org, name: o.name || o.handle, handle: o.name && o.name !== o.handle ? o.handle : '', createdAt: o.createdAt, type: o.type, stewards, members: o.members,
      test: stewards.length > 0 && stewards.every((p) => testPeople.has(p)),
    });
  }
  return out.sort((a, b) => (b.createdAt ?? 0) - (a.createdAt ?? 0) || a.name.localeCompare(b.name));
}
