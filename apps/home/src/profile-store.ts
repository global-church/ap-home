// The Impact home's profile store — the member's COMMUNITY CONTACT profile (name/email/phone/org),
// re-used across community apps. spec 278: persisted in the member's PER-PERSON ENCRYPTED vault at demo-mcp
// (the `vault:impact-profile` record, sealed under the member's own GCP Cloud KMS KEK), NOT browser storage.
//
// spec 288 §6 / ADR-0044 — the home reaches this THROUGH a2a (never the browser → /mcp direct path): it
// POSTs the member's address to the same-origin `/a2a/mcp/profile/{get,set}` agentic route (CSRF-protected,
// edge-admitted when the deployment requires the edge). demo-a2a forwards to demo-mcp over the service-MAC
// `/tools/{get,set}_impact_profile` (owner-own; demo-a2a asserts the principal — parity with the open demo
// OAuth mint). The home holds no key material and no copy. No vault-key binding (the member hasn't run the
// connected-custodian ceremony at /vault-key) ⇒ fail-closed (`vault_key_unauthorized`).

import type { Address } from '@agenticprimitives/types';
import { ensureCsrfToken, csrfHeaders } from './csrf';
import { SESSION_KEY } from './context/session';
import { readSsoCookie } from './lib/sso-cookie';
import {
  hydrateLocationFields,
  locationFieldFilled,
  locationFieldValue,
  persistLocationFields,
  type ProfileLocation,
} from './lib/profile-location';

export type { LocationPrecision, ProfileLocation } from './lib/profile-location';
export { formatLocation, normalizeLocation, projectLocationForShare } from './lib/profile-location';

/** The broker home-session token the InteractionsDO verifies (self-gated record ops). */
function homeBearer(): string {
  try {
    const raw = localStorage.getItem(SESSION_KEY);
    const t = raw ? (JSON.parse(raw) as { token?: string }).token : undefined;
    if (t) return t;
  } catch { /* fall through */ }
  return readSsoCookie()?.token ?? '';
}

export interface ImpactContactProfile {
  /** Display name — first/last let community apps render a friendly header like
   *  "Rich Pedersen" instead of the handle. Identity-level; the handle remains the
   *  canonical id. Held at Impact, re-used across every community app. */
  firstName?: string;
  lastName?: string;
  email?: string;
  phone?: string;
  /**
   * Structured location the person chose to share. Precision is country, state/province,
   * city, or street address. Apps granted this profile receive only that precision.
   * Private vault PII — never published as a public `approf:` facet.
   */
  location?: ProfileLocation;
  /** Legacy alias of `location.country`. Kept so existing grants and required=country still work. */
  country?: string;
  /** Legacy alias of `location.locality` when precision is city or address. */
  city?: string;
  /** For church / organization / network adopters or members — held at Impact because
   *  "the org you're part of" is a community-wide identity fact, not app-specific. */
  organizationName?: string;
  organizationCountry?: string;
}

export interface StoredAttestation {
  docHash: string;
  docId: string;
  signedAt: number;
  consentBoundTo: string;
}

export interface ImpactStoredProfile {
  v: 1;
  contact?: ImpactContactProfile;
  /** Community-wide attestations the member has signed at their home, re-used across
   *  relying apps. WEA Statement of Faith is the canonical example (signed once at
   *  Impact, every faith-aligned community app gets the same attestation receipt). */
  attestations?: {
    wea?: StoredAttestation;
  };
}

export type ImpactContactScalarKey = Exclude<keyof ImpactContactProfile, 'location'>;
export type ImpactProfileFieldKey = keyof ImpactContactProfile;

export const SHAREABLE_PROFILE_KEYS: readonly ImpactProfileFieldKey[] = [
  'firstName', 'lastName', 'email', 'phone', 'location', 'country', 'city',
  'organizationName', 'organizationCountry',
];

export function hydrateContact(contact: ImpactContactProfile = {}): ImpactContactProfile {
  return hydrateLocationFields(contact);
}

export function persistContact(contact: ImpactContactProfile): ImpactContactProfile {
  return persistLocationFields(contact);
}

export function contactFieldFilled(contact: ImpactContactProfile, key: ImpactProfileFieldKey): boolean {
  if (key === 'location' || key === 'country' || key === 'city') return locationFieldFilled(contact, key);
  return Boolean((contact[key] ?? '').trim());
}

export function contactFieldValue(contact: ImpactContactProfile, key: ImpactProfileFieldKey): string {
  if (key === 'location' || key === 'country' || key === 'city') return locationFieldValue(contact, key);
  return (contact[key] ?? '').trim();
}

/** Raised when the member has no vault-key binding yet (must run the /vault-key ceremony first). */
export class VaultKeyUnauthorizedError extends Error {
  constructor() {
    super('vault_key_unauthorized');
    this.name = 'VaultKeyUnauthorizedError';
  }
}

/** Raised when the member's INTERACTIONS plane isn't enabled (no/stale grant on their InteractionsDO).
 *  DISTINCT from the vault key — the record lives on the DO, gated by the interactions grant, not the
 *  KEK. The UI enables that plane (silent on KMS/wallet homes) rather than mislabeling it "vault key". */
export class InteractionsNotEnabledError extends Error {
  constructor() {
    super('interactions_not_enabled');
    this.name = 'InteractionsNotEnabledError';
  }
}

export const PROFILE_FIELDS: { key: ImpactContactScalarKey; label: string; type: 'email' | 'tel' | 'text'; placeholder: string; help: string }[] = [
  { key: 'firstName',           label: 'First name',            type: 'text',  placeholder: 'Rich',                     help: 'Used to greet you across community apps.' },
  { key: 'lastName',            label: 'Last name',             type: 'text',  placeholder: 'Pedersen',                 help: 'Used together with your first name to render a friendly display name.' },
  { key: 'email',               label: 'Email',                 type: 'email', placeholder: 'you@example.com',          help: 'How community apps reach you. Shared on your terms.' },
  { key: 'phone',               label: 'Phone',                 type: 'tel',   placeholder: '+1 555 0100',              help: 'Optional. Shared only when you explicitly grant the scope.' },
  { key: 'organizationName',    label: 'Organization name',     type: 'text',  placeholder: 'Grace Community Church',    help: 'If you act on behalf of a church, organization, or network in the community.' },
  { key: 'organizationCountry', label: 'Organization country',  type: 'text',  placeholder: 'United States',            help: 'Where your organization is based.' },
];

// ─── Owner-own profile via the person's InteractionsDO (spec 323 W2 / V-1 remediation) ──────────────
// Owner-own: demo-a2a asserts the member's principal over service-MAC to demo-mcp, which gates every op on
// the per-person vault-key authorization (read/write). CSRF-protected like every other /a2a/* mutating call.

// spec 323 W2 (V-1 remediation): owner-own profile is now a DELEGATION-authorized, self-gated
// record on the person's InteractionsDO (`record.get`/`record.put`, recordType `impact-profile`),
// KEK-encrypted at demo-mcp exactly as before — but no longer a bearer/service-MAC path any caller
// could aim at another principal. The DO verifies the broker home session and that its SA IS the
// principal; the interactions grant's `vault:impact-profile` scope + the vault-key gate bound it.
async function postProfile(path: 'get' | 'set', principal: Address, data?: ImpactStoredProfile): Promise<Record<string, unknown>> {
  await ensureCsrfToken();
  const session = homeBearer();
  if (!session) throw new Error(`profile ${path} failed: no home session`);
  const op = path === 'get' ? 'record.get' : 'record.put';
  const res = await fetch(`/a2a/interactions/${principal.toLowerCase()}/${op}`, {
    method: 'POST',
    credentials: 'include',
    headers: { 'content-type': 'application/json', ...csrfHeaders() },
    body: JSON.stringify({ session, recordType: 'impact-profile', ...(data !== undefined ? { record: data } : {}) }),
  });
  const body = (await res.json().catch(() => ({}))) as Record<string, unknown>;
  if (body.error === 'vault_key_unauthorized') throw new VaultKeyUnauthorizedError();
  // 409 from the InteractionsDO = the person's interactions plane isn't enabled (no grant / stale grant,
  // both carry "interactions grant" in the message). The caller enables that plane, NOT the vault key.
  if (res.status === 409) throw new InteractionsNotEnabledError();
  if (!res.ok) throw new Error(`profile ${path} failed: ${String(body.error ?? res.status)}`);
  return body;
}

// ── Personal vault-records viewer (spec 315 Manage) ───────────────────────────────────────────────
// "See your personal vault records like we do for org." The person self-reads their OWN vault over
// the interactions grant (self-gated `record.get`). This is the SELF-READABLE set — it matches the
// InteractionsDO `CAPABILITY_RECORDS` whitelist, NOT the whole vault: the person's own list is
// whitelist-gated by design (unlike the org viewer, which lists everything through the stewardship
// delegation's record scope). Showing every vault record would need a server `record.list` op.
// `skills.data` — the person's CAPABILITY RECORD (capability claim credentials); record-type key is legacy.
export const PERSON_CAPABILITY_RECORDS = ['impact-profile', 'skills.data', 'home.manifest', 'control-events.data', 'security.credentials', 'security.channels'] as const;
export type PersonRecordType = (typeof PERSON_CAPABILITY_RECORDS)[number];

/** A record ref the person's vault list returns (spec 315 vault viewer). */
export interface PersonVaultRecordRef {
  record_type: string;
  updated_at: string;
}

/** List the person's OWN Home-managed vault record types (self-gated `record.list`). demo-mcp scope-filters
 *  to the interactions grant, so app-specific records (written under a DIFFERENT app's grant, e.g. a relying
 *  app's) never appear — least-privilege. Same fail-closed surface as the reads below. */
export async function listPersonRecords(principal: Address): Promise<PersonVaultRecordRef[]> {
  await ensureCsrfToken();
  const session = homeBearer();
  if (!session) throw new Error('record list failed: no home session');
  const res = await fetch(`/a2a/interactions/${principal.toLowerCase()}/record.list`, {
    method: 'POST',
    credentials: 'include',
    headers: { 'content-type': 'application/json', ...csrfHeaders() },
    body: JSON.stringify({ session }),
  });
  const body = (await res.json().catch(() => ({}))) as { records?: Array<{ resource?: string; record_type?: string; updatedAt?: string; updated_at?: string }>; error?: string };
  if (body?.error === 'vault_key_unauthorized') throw new VaultKeyUnauthorizedError();
  if (res.status === 409) throw new InteractionsNotEnabledError();
  if (!res.ok) throw new Error(`record list failed: ${String(body.error ?? res.status)}`);
  return (body.records ?? []).map((r) => ({ record_type: r.resource ?? r.record_type ?? '', updated_at: r.updatedAt ?? r.updated_at ?? '' })).filter((r) => r.record_type);
}

/** Read one of the person's OWN records from their vault (self-gated `record.get`; reads are scope-gated at
 *  demo-mcp, not whitelisted). Same fail-closed surface: {@link VaultKeyUnauthorizedError} (activate the
 *  vault key) / {@link InteractionsNotEnabledError} (enable the interactions plane). `null` = no such record. */
export async function readPersonRecord(principal: Address, recordType: string): Promise<unknown> {
  await ensureCsrfToken();
  const session = homeBearer();
  if (!session) throw new Error(`record ${recordType} read failed: no home session`);
  const res = await fetch(`/a2a/interactions/${principal.toLowerCase()}/record.get`, {
    method: 'POST',
    credentials: 'include',
    headers: { 'content-type': 'application/json', ...csrfHeaders() },
    body: JSON.stringify({ session, recordType }),
  });
  const body = (await res.json().catch(() => ({}))) as Record<string, unknown>;
  if (body.error === 'vault_key_unauthorized') throw new VaultKeyUnauthorizedError();
  if (res.status === 409) throw new InteractionsNotEnabledError();
  if (!res.ok) throw new Error(`record ${recordType} read failed: ${String(body.error ?? res.status)}`);
  return body.record ?? null;
}

/** Write one of the person's OWN Home-managed records (self-gated `record.put`; the runtime whitelists the record
 *  types it accepts — `PERSON_CAPABILITY_RECORDS` mirrors that list). Same fail-closed surface as the reads. */
export async function writePersonRecord(principal: Address, recordType: PersonRecordType, record: unknown): Promise<void> {
  await ensureCsrfToken();
  const session = homeBearer();
  if (!session) throw new Error(`record ${recordType} write failed: no home session`);
  const res = await fetch(`/a2a/interactions/${principal.toLowerCase()}/record.put`, {
    method: 'POST',
    credentials: 'include',
    headers: { 'content-type': 'application/json', ...csrfHeaders() },
    body: JSON.stringify({ session, recordType, record }),
  });
  const body = (await res.json().catch(() => ({}))) as Record<string, unknown>;
  if (body.error === 'vault_key_unauthorized') throw new VaultKeyUnauthorizedError();
  if (res.status === 409) throw new InteractionsNotEnabledError();
  if (!res.ok) throw new Error(`record ${recordType} write failed: ${String(body.error ?? res.status)}`);
}

/** Read the member's encrypted community profile from their vault. Returns an empty profile if the
 *  member has never saved one. Throws `VaultKeyUnauthorizedError` if they haven't activated their
 *  vault key (run the /vault-key ceremony) yet. */
/**
 * A short-lived memo of the profile read, per address. Measured on a Gather27 publish (2026-10-13): this one
 * record was read EIGHT times in a row, 2–3 s each — the session shell re-read it on every profile refresh,
 * and the sign-in sheet read it twice more. Callers asking while a read is in flight share it; a result is
 * reused for a few seconds; a write drops it. Failures are never kept (a vault key that is not bound yet
 * must be retried, which is what seedImpactProfileFields does).
 */
// 60 s (2026-10-21; was 15): a Gather publish reads it ~20 s after sign-in seeded it, and only this tab writes it.
const PROFILE_MEMO_MS = 60_000;
const profileMemo = new Map<string, { at: number; value: Promise<ImpactStoredProfile> }>();
function forgetProfile(addr: Address): void {
  profileMemo.delete(addr.toLowerCase());
}

export async function loadImpactProfile(addr: Address): Promise<ImpactStoredProfile> {
  const key = addr.toLowerCase();
  const hit = profileMemo.get(key);
  if (hit && Date.now() - hit.at < PROFILE_MEMO_MS) return hit.value;
  const value = (async (): Promise<ImpactStoredProfile> => {
    const out = await postProfile('get', addr);
    const record = out.record as ImpactStoredProfile | null | undefined;
    if (record && record.v === 1) {
      return { ...record, contact: hydrateContact(record.contact ?? {}) };
    }
    return { v: 1 };
  })();
  profileMemo.set(key, { at: Date.now(), value });
  value.catch(() => { if (profileMemo.get(key)?.value === value) profileMemo.delete(key); });
  return value;
}

/** Seal the member's community profile into their vault under their own KEK. Throws
 *  `VaultKeyUnauthorizedError` if they haven't activated their vault key yet. */
export async function saveImpactProfile(addr: Address, profile: ImpactStoredProfile): Promise<void> {
  const next: ImpactStoredProfile = {
    ...profile,
    contact: profile.contact ? persistContact(profile.contact) : profile.contact,
  };
  forgetProfile(addr);
  const out = await postProfile('set', addr, next);
  if (out.ok !== true) {
    forgetProfile(addr);
    throw new Error(`save failed: ${String(out.error ?? 'unknown')}`);
  }
  // What was just written IS the record now: keep it, rather than paying a 1.5–2 s vault read to learn it again
  // (the sign-in seed was re-read at org creation, 2026-10-21 timeline).
  profileMemo.set(addr.toLowerCase(), { at: Date.now(), value: Promise.resolve(profile) });
}

/** Seed vault-profile fields from a CONNECTION (metadata-tiers doctrine: a verified contact point is
 *  tier-1 PII — it belongs in the private vault, seeded automatically). FILL-ONLY-EMPTY: a value the
 *  member already saved is never overwritten. Best-effort with a short retry — the vault-key bind
 *  (`activateVault`, fired in parallel by the bootstrap flows) may still be landing when this runs. */
export async function seedImpactProfileFields(addr: Address, fields: Partial<ImpactContactProfile>): Promise<void> {
  for (let attempt = 0; attempt < 5; attempt++) {
    try {
      const cur = await loadImpactProfile(addr);
      const contact: ImpactContactProfile = { ...(cur.contact ?? {}) };
      let changed = false;
      for (const [k, v] of Object.entries(fields)) {
        if (k === 'location' || typeof v !== 'string' || !v) continue;
        const key = k as ImpactContactScalarKey;
        if (!contact[key]) { contact[key] = v; changed = true; }
      }
      if (changed) await saveImpactProfile(addr, { ...cur, contact });
      return;
    } catch (e) {
      if (e instanceof VaultKeyUnauthorizedError) {
        await new Promise((r) => setTimeout(r, 2500)); // key bind racing us — retry
        continue;
      }
      console.warn('[profile-seed] connection data not seeded (edit it on /profile):', e);
      return;
    }
  }
  console.warn('[profile-seed] vault key never bound — connection data not seeded (edit it on /profile)');
}
