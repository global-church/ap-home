// THE OPERATOR DIRECTORY (Global.Church, 2026-10-23; design: gc-estate/docs/operator-workspace.md).
//
// Contact emails for every account, kept in the OPERATOR ORGANIZATION's vault (records `contact:<account>`), written
// and read only through the operator org's InteractionsDO. This file is the policy, pure and tested; the DO applies it.
//
//  - A person's email is recorded only when their own GCID session proves it: the session's sign-in identity is
//    `email#<sha256(email)>` (custody-grade) or `<sha256(email)>` (login-grade). No secret, no server assertion.
//  - Admins see masked addresses. A full address leaves by a REVEAL (one account, recorded) or an EXPORT that a second,
//    different admin approved (recorded at request, approval and download; downloaded once, within a time limit).
//  - Every event lands in the audit log before the data is returned.

export const CONTACT_PREFIX = 'contact:';
export const AUDIT_LOG = 'directory.audit:log';
export const EXPORTS_DOC = 'export:requests';
/** The record scope the directory grant must carry, exactly (operator org → interactions service, read+write). */
export const DIRECTORY_SCOPE = ['vault:contact:*', 'vault:directory.audit:*', 'vault:export:*'] as const;

/** A request waits this long for a second admin. */
export const EXPORT_APPROVAL_WINDOW_MS = 24 * 60 * 60 * 1000;
/** Once approved, the requester has this long to download it, once. */
export const EXPORT_FETCH_WINDOW_MS = 30 * 60 * 1000;
export const AUDIT_KEPT = 1000;
export const EXPORTS_KEPT = 200;
export const MAX_EXPORT_ACCOUNTS = 5000;

const ADDRESS = /^0x[0-9a-f]{40}$/;
const EMAIL = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

export const contactKey = (account: string): string => `${CONTACT_PREFIX}${account.toLowerCase()}`;
export const isAccount = (a: unknown): a is string => typeof a === 'string' && ADDRESS.test(a.toLowerCase());
export const cleanEmail = (e: unknown): string | null => {
  const s = typeof e === 'string' ? e.trim().toLowerCase() : '';
  return EMAIL.test(s) && s.length <= 254 ? s : null;
};

/** A contact as first written (2026-10-23): the email in the clear inside the vault record. Read until sealed. */
export interface PlainContact {
  v: 2;
  email: string;
  verifiedAt: number;
  /** 'email-sign-in' | 'org-default:<creator>' | 'org-verified:<steward>' | 'import:<old source>' */
  source: string;
}

/** A sealed contact (2026-10-27, directory-seal.ts): the email encrypted under the directory's data key; the masked
 *  form in the clear so the masked list needs no decryption. `source` carries no address (who set an org's contact is
 *  in the audit log). */
export interface SealedContact {
  v: 3;
  sealed: string;
  masked: string;
  verifiedAt: number;
  /** 'email-sign-in' | 'org-default' | 'org-verified' | 'import' */
  source: string;
}

export type ContactRecord = PlainContact | SealedContact;

export function readContact(raw: unknown): ContactRecord | null {
  const r = raw as { v?: unknown; email?: unknown; sealed?: unknown; masked?: unknown; verifiedAt?: unknown; source?: unknown } | null;
  if (!r || typeof r.verifiedAt !== 'number') return null;
  const source = typeof r.source === 'string' ? r.source : '';
  if (r.v === 3 && typeof r.sealed === 'string' && typeof r.masked === 'string') return { v: 3, sealed: r.sealed, masked: r.masked, verifiedAt: r.verifiedAt, source };
  if (r.v === 2 && typeof r.email === 'string') return { v: 2, email: r.email, verifiedAt: r.verifiedAt, source };
  return null;
}

/** The source as the Admin list shows it: its kind only, never an address (a v2 source carried the setter's). */
export const sourceKind = (source: string): string => source.split(':')[0] ?? '';

/** "pastor@grace.org" -> "pa•••r@g•••.org". Enough to recognise, not enough to use. */
export function maskEmail(email: string): string {
  const [local = '', domain = ''] = email.split('@');
  const dot = domain.lastIndexOf('.');
  const host = dot > 0 ? domain.slice(0, dot) : domain;
  const tld = dot > 0 ? domain.slice(dot) : '';
  const l = local.length <= 2 ? `${local.slice(0, 1)}•••` : `${local.slice(0, 2)}•••${local.slice(-1)}`;
  return `${l}@${host.slice(0, 1)}•••${tld}`;
}

export async function sha256Hex(s: string): Promise<string> {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** Does this verified session's sign-in identity prove this email? (See kv-indexer emailHash / email-verify.ts.) */
export async function sessionProvesEmail(principal: { kind: string; id: string } | undefined, email: string): Promise<boolean> {
  if (!principal) return false;
  const h = await sha256Hex(email.trim().toLowerCase());
  if (principal.kind === 'oidc') return principal.id.toLowerCase() === `email#${h}`;
  if (principal.kind === 'email') return principal.id.toLowerCase() === h;
  return false;
}

// ── Audit ───────────────────────────────────────────────────────────────────────────────────────────────────────

export type AuditKind = 'list' | 'reveal' | 'export-request' | 'export-approve' | 'export-fetch' | 'export-deny' | 'import' | 'enable' | 'old-removed' | 'seal' | 'org-contact';
export interface AuditEntry { at: number; by: string; kind: AuditKind; accounts?: number; account?: string; exportId?: string; note?: string }

/** Bounded, but list views are dropped first (security review 2026-10-23, #3): opening the masked list again and
 *  again must not push a reveal or an export out of the log. Only when the log is all reveals/exports does the
 *  oldest of those go. */
export function appendAudit(log: AuditEntry[] | null | undefined, entry: AuditEntry): AuditEntry[] {
  const all = [...(Array.isArray(log) ? log : []), { ...entry, by: entry.by.toLowerCase() }];
  let over = all.length - AUDIT_KEPT;
  if (over <= 0) return all;
  const kept = all.filter((e) => (e.kind === 'list' && over > 0 ? (over--, false) : true));
  return kept.slice(-AUDIT_KEPT);
}

// ── Exports: request -> a DIFFERENT admin approves -> the requester downloads once ──────────────────────────────

export interface ExportRequest {
  id: string;
  app: string;
  /** Frozen at request time: what is approved is exactly what is downloaded. */
  accounts: string[];
  requestedBy: string;
  requestedAt: number;
  note?: string;
  approvedBy?: string;
  approvedAt?: number;
  deniedBy?: string;
  deniedAt?: number;
  fetchedAt?: number;
}

export type ExportStatus = 'pending' | 'approved' | 'downloaded' | 'denied' | 'expired';

export function exportStatus(r: ExportRequest, now: number): ExportStatus {
  if (r.fetchedAt) return 'downloaded';
  if (r.deniedAt) return 'denied';
  if (r.approvedAt) return now - r.approvedAt <= EXPORT_FETCH_WINDOW_MS ? 'approved' : 'expired';
  return now - r.requestedAt <= EXPORT_APPROVAL_WINDOW_MS ? 'pending' : 'expired';
}

export type Verdict = { ok: true } | { ok: false; reason: string };

export function newExportRequest(input: { id: string; app: string; accounts: unknown; requestedBy: string; now: number; note?: unknown }): ExportRequest | { error: string } {
  const accounts = Array.isArray(input.accounts) ? [...new Set(input.accounts.filter(isAccount).map((a) => a.toLowerCase()))] : [];
  if (!accounts.length) return { error: 'nothing to export' };
  if (accounts.length > MAX_EXPORT_ACCOUNTS) return { error: `at most ${MAX_EXPORT_ACCOUNTS} accounts per export` };
  if (!/^[a-z0-9-]{1,40}$/.test(input.app)) return { error: 'app required' };
  const note = typeof input.note === 'string' ? input.note.replace(/\s+/g, ' ').trim().slice(0, 200) : '';
  return { id: input.id, app: input.app, accounts, requestedBy: input.requestedBy.toLowerCase(), requestedAt: input.now, ...(note ? { note } : {}) };
}

/** Separation of duties: the approver is an admin (checked by the caller) and NOT the requester. */
export function canApprove(r: ExportRequest, approver: string, now: number): Verdict {
  const s = exportStatus(r, now);
  if (s !== 'pending') return { ok: false, reason: `this export is ${s}` };
  if (approver.toLowerCase() === r.requestedBy) return { ok: false, reason: 'a second admin must approve: you requested this export' };
  return { ok: true };
}

export function canDeny(r: ExportRequest, now: number): Verdict {
  const s = exportStatus(r, now);
  return s === 'pending' || s === 'approved' ? { ok: true } : { ok: false, reason: `this export is ${s}` };
}

/** Only the requester, only once, only while approved and inside the window. */
export function canFetch(r: ExportRequest, by: string, now: number): Verdict {
  const s = exportStatus(r, now);
  if (s !== 'approved') return { ok: false, reason: s === 'pending' ? 'waiting for a second admin to approve' : `this export is ${s}` };
  if (by.toLowerCase() !== r.requestedBy) return { ok: false, reason: 'only the admin who requested this export can download it' };
  return { ok: true };
}

export function keepExports(list: ExportRequest[] | null | undefined): ExportRequest[] {
  return (Array.isArray(list) ? list : []).slice(-EXPORTS_KEPT);
}

/** What the list of requests shows: never the accounts themselves, only how many. */
export function exportSummary(r: ExportRequest, now: number) {
  const { accounts, ...rest } = r;
  return { ...rest, count: accounts.length, status: exportStatus(r, now) };
}
