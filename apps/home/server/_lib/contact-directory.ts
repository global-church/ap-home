// THE OPERATOR'S CONTACT DIRECTORY (Global.Church, 2026-10-21) — the email each person signs in with, readable by
// the Home's admins and nobody else.
//
// WHY. Paul: "as the home operator, we will want access to view emails if needed." Sign-in keeps only
// SHA-256(email) (kv-indexer.ts), on purpose, and that does not change: login holds no readable address.
//
// WHAT. The RECORD of a person's contact email is their own vault profile (`impact-profile` → `contact.email`),
// seeded at sign-in by EmailAuthCard → seedImpactProfileFields. This file keeps the operator's COPY of it:
//  - written at the moment an address is verified (email-verify.ts), so every account from launch has one;
//  - encrypted with AES-256-GCM under CONTACT_DIRECTORY_KEY (a deployment secret, backed up in the Azure vault);
//    the person's address is the AAD, so a record cannot be moved onto another account; a leaked KV is unreadable;
//  - read only through the Admin lookup (admin.ts, HOME_ADMINS), and every read is recorded ON the record
//    (`lookups`: who and when, the last 50) and in the server log.
// No key configured → nothing is written and the lookup says so. A failure here never fails a sign-in.
import type { Env, KVNamespace } from './server-broker';

export interface ContactRecordV1 {
  v: 1;
  /** base64 IV + AES-GCM ciphertext of the email. */
  iv: string;
  ct: string;
  /** When this address was last verified by a sign-in code (ms). */
  verifiedAt: number;
  /** How it was verified: 'email-sign-in' or 'email-link' (added to an existing account). */
  source: string;
  /** Who looked it up in Admin, and when (newest last, at most 50). */
  lookups?: { by: string; at: number }[];
}

export interface ContactLookup {
  email: string;
  verifiedAt: number;
  source: string;
}

const ADDRESS = /^0x[0-9a-f]{40}$/;
const contactKey = (address: string): string => `contact:${address.toLowerCase()}`;
const LOOKUPS_KEPT = 50;

const b64 = (bytes: Uint8Array): string => btoa(String.fromCharCode(...bytes));
const unb64 = (s: string): Uint8Array => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

/** `eip155:<chain>:0x…` or a bare address → the lower-case address, or null. */
export function accountAddress(agent: string): string | null {
  const a = String(agent ?? '').split(':').pop()?.toLowerCase() ?? '';
  return ADDRESS.test(a) ? a : null;
}

export function contactDirectoryEnabled(env: Pick<Env, 'CONTACT_DIRECTORY_KEY'>): boolean {
  try {
    return unb64((env.CONTACT_DIRECTORY_KEY ?? '').trim()).length === 32;
  } catch {
    return false;
  }
}

async function key(env: Pick<Env, 'CONTACT_DIRECTORY_KEY'>): Promise<CryptoKey | null> {
  if (!contactDirectoryEnabled(env)) return null;
  return crypto.subtle.importKey('raw', unb64(env.CONTACT_DIRECTORY_KEY!.trim()), 'AES-GCM', false, ['encrypt', 'decrypt']);
}

async function encrypt(k: CryptoKey, address: string, email: string): Promise<{ iv: string; ct: string }> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: new TextEncoder().encode(address) }, k, new TextEncoder().encode(email));
  return { iv: b64(iv), ct: b64(new Uint8Array(ct)) };
}

async function decrypt(k: CryptoKey, address: string, rec: ContactRecordV1): Promise<string> {
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(rec.iv), additionalData: new TextEncoder().encode(address) }, k, unb64(rec.ct));
  return new TextDecoder().decode(pt);
}

async function readRecord(kv: KVNamespace, address: string): Promise<ContactRecordV1 | null> {
  try {
    const raw = await kv.get(contactKey(address));
    const r = raw ? (JSON.parse(raw) as ContactRecordV1) : null;
    return r && r.v === 1 && r.iv && r.ct ? r : null;
  } catch {
    return null;
  }
}

/**
 * Keep the operator's copy of a just-verified address. The newest verified address wins (a person who changed
 * the email they sign in with is reachable at the new one); the lookup history is kept. Never throws.
 */
export async function recordContactEmail(env: Env, agent: string, email: string, source: string, now = Date.now()): Promise<void> {
  try {
    const address = accountAddress(agent);
    const k = await key(env);
    const clean = email.trim().toLowerCase();
    if (!address || !k || !clean.includes('@')) return;
    const prev = await readRecord(env.AUTH_CODES, address);
    const sealed = await encrypt(k, address, clean);
    const next: ContactRecordV1 = { v: 1, ...sealed, verifiedAt: now, source, ...(prev?.lookups?.length ? { lookups: prev.lookups } : {}) };
    await env.AUTH_CODES.put(contactKey(address), JSON.stringify(next));
  } catch (e) {
    console.warn('[contact-directory] not recorded:', e instanceof Error ? e.message : e);
  }
}

/** An admin's read of one account's contact email. Records who looked, on the record and in the log. */
export async function lookUpContactEmail(env: Env, address: string, by: string, now = Date.now()): Promise<ContactLookup | null> {
  const a = accountAddress(address);
  const k = await key(env);
  if (!a || !k) return null;
  const rec = await readRecord(env.AUTH_CODES, a);
  if (!rec) return null;
  const email = await decrypt(k, a, rec);
  const lookups = [...(rec.lookups ?? []), { by: by.toLowerCase(), at: now }].slice(-LOOKUPS_KEPT);
  await env.AUTH_CODES.put(contactKey(a), JSON.stringify({ ...rec, lookups } satisfies ContactRecordV1));
  console.info('[contact-directory] admin lookup', { account: a, by: by.toLowerCase(), at: new Date(now).toISOString() });
  return { email, verifiedAt: rec.verifiedAt, source: rec.source };
}

/** Who has looked this account's email up (for the Admin page). */
export async function contactLookups(kv: KVNamespace, address: string): Promise<{ by: string; at: number }[]> {
  const a = accountAddress(address);
  return a ? ((await readRecord(kv, a))?.lookups ?? []) : [];
}
