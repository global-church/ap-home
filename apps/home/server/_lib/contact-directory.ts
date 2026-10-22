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
//  - read only through Admin's Organizations tab (admin.ts, HOME_ADMINS), and every view of it is recorded
//    (`contact-views:log`: who, when, which listing, how many) and in the server log.
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
  /** Who looked it up in the old one-at-a-time Admin lookup (2026-10-21 to 10-22); kept on records that have it. */
  lookups?: { by: string; at: number }[];
}

export interface ContactLookup {
  email: string;
  verifiedAt: number;
  source: string;
}

const ADDRESS = /^0x[0-9a-f]{40}$/;
const contactKey = (address: string): string => `contact:${address.toLowerCase()}`;

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

/**
 * Admin's Organizations tab (2026-10-22): read the contact email of each account, for one listing. Unlike the old
 * one-at-a-time lookup this writes nothing per account; the VIEW is what is recorded (recordContactView), once, with
 * who opened it, when, and how many addresses it showed. A record that does not open under this key for this
 * account (moved, or sealed under another key) is left out and logged, never shown.
 */
export async function readContactEmails(env: Env, addresses: string[]): Promise<Map<string, ContactLookup>> {
  const out = new Map<string, ContactLookup>();
  const k = await key(env);
  if (!k) return out;
  const unique = [...new Set(addresses.map(accountAddress).filter((a): a is string => !!a))];
  for (let i = 0; i < unique.length; i += 50) {
    await Promise.all(unique.slice(i, i + 50).map(async (a) => {
      const rec = await readRecord(env.AUTH_CODES, a);
      if (!rec) return;
      try {
        out.set(a, { email: await decrypt(k, a, rec), verifiedAt: rec.verifiedAt, source: rec.source });
      } catch {
        console.warn('[contact-directory] a record did not open for its account', { account: a });
      }
    }));
  }
  return out;
}

export interface ContactView { by: string; at: number; what: string; count: number }
const VIEWS_KEY = 'contact-views:log';
const VIEWS_KEPT = 500;

/** Record that an admin was shown contact emails: who, when, which listing, how many. The last 500 are kept. */
export async function recordContactView(kv: KVNamespace, view: ContactView): Promise<void> {
  let log: ContactView[] = [];
  try {
    log = JSON.parse((await kv.get(VIEWS_KEY)) ?? '[]') as ContactView[];
  } catch {
    log = [];
  }
  const entry = { ...view, by: view.by.toLowerCase() };
  await kv.put(VIEWS_KEY, JSON.stringify([...log, entry].slice(-VIEWS_KEPT)));
  console.info('[contact-directory] admin view', { ...entry, at: new Date(view.at).toISOString() });
}

/** The recorded views, newest first. */
export async function contactViews(kv: KVNamespace, limit = 20): Promise<ContactView[]> {
  try {
    return (JSON.parse((await kv.get(VIEWS_KEY)) ?? '[]') as ContactView[]).slice(-limit).reverse();
  } catch {
    return [];
  }
}
