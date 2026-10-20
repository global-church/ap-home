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
