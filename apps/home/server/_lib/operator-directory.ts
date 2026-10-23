// GCID's side of the OPERATOR DIRECTORY (2026-10-23; design: gc-estate/docs/operator-workspace.md).
//
// The directory itself lives in the operator org's vault and is reached only through the operator org's InteractionsDO
// (agent-runtime operator-directory-ops.ts). This file is how the Home talks to it:
//  - recordVerifiedEmail: after an email code is checked, record that address for that account. The DO refuses any
//    address the session does not prove, so this sends a short-lived session naming the sign-in hash.
//  - operatorAdmin: is this person an admin, i.e. a steward of the operator org, verified on-chain (cached 60 s)?
//  - directoryOp: one admin op, carrying the admin's own session and stewardship grant to the DO.
// Unset HOME_OPERATOR_ORG = the directory is off and the Home keeps its previous behaviour (a switch, not a fallback).
import { mintAgentSession } from '@agenticprimitives/connect';
import { getServer, resolveOrigin, type Env, type KVNamespace } from './server-broker';
import { verifyStewardship } from './verify-stewardship';
import type { IncomingDelegation } from './verify-delegation';
import { emailHash } from '../../src/lib/kv-indexer';

const ADDRESS = /^0x[0-9a-f]{40}$/;

export function operatorOrg(env: Pick<Env, 'HOME_OPERATOR_ORG'>): string | null {
  const a = (env.HOME_OPERATOR_ORG ?? '').trim().toLowerCase();
  return ADDRESS.test(a) ? a : null;
}

function a2aBase(env: Env): string {
  // The same runtime base the Home's other InteractionsDO calls use (connect/channels.ts callInteractions).
  return (env.A2A_CUSTODY_URL || '').replace(/\/$/, '');
}

/** One op on the operator org's InteractionsDO. */
export async function directoryOp(env: Env, op: string, body: Record<string, unknown>): Promise<{ status: number; body: Record<string, unknown> }> {
  const org = operatorOrg(env);
  const base = a2aBase(env);
  if (!org || !base) return { status: 503, body: { ok: false, error: 'the operator directory is not configured' } };
  const res = await fetch(`${base}/interactions/${org}/${op}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  }).catch(() => null);
  if (!res) return { status: 502, body: { ok: false, error: 'the directory service did not answer' } };
  return { status: res.status, body: (await res.json().catch(() => ({}))) as Record<string, unknown> };
}

/**
 * Record the address a person just proved with a code. A two-minute session names that address's hash, so the
 * directory accepts this address and no other, for this account and no other. Never throws, never fails a sign-in.
 */
/** A two-minute session for `agent` whose sign-in subject is this email's hash: GCID's statement that the address was
 *  just verified with a code. The DO accepts an address only with such a session. It never leaves the server. */
async function emailSessionFor(env: Env, request: Request, agent: string, clean: string): Promise<string> {
  const { signer } = await getServer(env);
  return mintAgentSession(
    {
      sub: agent.toLowerCase() as Parameters<typeof mintAgentSession>[0]['sub'],
      principal: { kind: 'email', id: await emailHash(clean), assurance: 'asserted', role: 'login-grade' },
      assurance: 'asserted',
      aud: env.DEMO_SSO_AUD ?? 'demo-sso',
      iss: resolveOrigin(request, env),
      ttlSeconds: 120,
    },
    signer,
  );
}

export async function recordVerifiedEmail(env: Env, request: Request, agent: string, email: string): Promise<void> {
  try {
    if (!operatorOrg(env)) return;
    const clean = email.trim().toLowerCase();
    const token = await emailSessionFor(env, request, agent, clean);
    const r = await directoryOp(env, 'directory.record', { session: token, email: clean });
    if (r.status !== 200) console.warn('[operator-directory] email not recorded', { status: r.status, error: r.body.error });
  } catch (e) {
    console.warn('[operator-directory] email not recorded:', e instanceof Error ? e.message : e);
  }
}

/** The person's link to an org and the stewardship grant on it (the grant is re-verified on-chain by the caller). */
export async function stewardshipFor(kv: KVNamespace, person: string, org: string): Promise<IncomingDelegation | undefined> {
  try {
    const raw = await kv.get(`related:${person.toLowerCase()}:${org.toLowerCase()}`);
    return raw ? ((JSON.parse(raw) as { stewardshipDelegation?: IncomingDelegation }).stewardshipDelegation ?? undefined) : undefined;
  } catch {
    return undefined;
  }
}

const adminCache = new Map<string, { at: number; stewardship: IncomingDelegation | null }>();
const ADMIN_CACHE_MS = 60_000;

/** An admin = a live, unrevoked stewardship grant from the operator org (60 s cache, so a revoke lands within a minute). */
export async function operatorAdmin(env: Env, person: string): Promise<IncomingDelegation | null> {
  const org = operatorOrg(env);
  const p = person.toLowerCase();
  if (!org || !ADDRESS.test(p)) return null;
  const hit = adminCache.get(p);
  if (hit && Date.now() - hit.at < ADMIN_CACHE_MS) return hit.stewardship;
  const wire = await stewardshipFor(env.AUTH_CODES, p, org);
  const ok = wire ? await verifyStewardship(env, org, p, wire).catch(() => false) : false;
  const stewardship = ok ? wire! : null;
  adminCache.set(p, { at: Date.now(), stewardship });
  return stewardship;
}

/** For tests. */
export function resetOperatorAdminCache(): void { adminCache.clear(); }

/** A two-minute Home session for `person`, minted by this Home for a server-to-DO call that the DO then gates on that
 *  person's ON-CHAIN stewardship. It never leaves the server. */
async function serverSessionFor(env: Env, request: Request, person: string): Promise<string> {
  const { signer } = await getServer(env);
  return mintAgentSession(
    {
      sub: person.toLowerCase() as Parameters<typeof mintAgentSession>[0]['sub'],
      principal: { kind: 'oidc', id: 'home#directory', assurance: 'asserted', role: 'login-grade' },
      assurance: 'asserted',
      aud: env.DEMO_SSO_AUD ?? 'demo-sso',
      iss: resolveOrigin(request, env),
      ttlSeconds: 120,
    },
    signer,
  );
}

/** A new organization's contact = its creator's verified email (copied by the DO, never supplied). Never throws. */
export async function recordOrgDefault(env: Env, request: Request, person: string, org: string, stewardship: unknown): Promise<void> {
  try {
    if (!operatorOrg(env) || !stewardship) return;
    const r = await directoryOp(env, 'directory.defaultOrg', { session: await serverSessionFor(env, request, person), org, stewardship });
    if (r.status !== 200) console.warn('[operator-directory] org default not recorded', { status: r.status, error: r.body.error });
  } catch (e) {
    console.warn('[operator-directory] org default not recorded:', e instanceof Error ? e.message : e);
  }
}

/** An organization's contact, changed after GCID checked the code sent to it. The session proves that address (only
 *  GCID can mint it); the DO also re-checks the person's stewardship of the org. */
export async function recordOrgVerified(env: Env, request: Request, person: string, org: string, email: string): Promise<{ ok: boolean; error?: string }> {
  const stewardship = await stewardshipFor(env.AUTH_CODES, person, org);
  const clean = email.trim().toLowerCase();
  const session = await emailSessionFor(env, request, person, clean);
  const r = await directoryOp(env, 'directory.recordOrg', { session, org, stewardship, email: clean });
  return r.status === 200 ? { ok: true } : { ok: false, error: String(r.body.error ?? `the directory answered ${r.status}`) };
}
