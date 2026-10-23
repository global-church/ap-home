// THE GATE — OIDC-subject custody (spec 235 §5; #2 per-subject signer, provider-neutral — Google OR YouVersion).
//
// demo-a2a is the SOLE holder of the master, so it is the ONLY party that can
// derive a member's per-subject custodian C_sub and compute their Smart Agent
// address. These helpers are the security boundary for the custody endpoints in
// index.ts (canonical `/custody/oidc/*`; `/custody/google/*` is the deprecated alias):
//
//   /custody/oidc/resolve            (broker → a2a, bridge-secret) — derive only
//   /custody/oidc/bootstrap-and-claim (client → a2a, custody session) — deploy + claim
//   /custody/oidc/sign                (client → a2a, custody session) — sign a digest
//
// Invariants enforced here (spec 235 §9):
//   - A client-facing call NEVER derives/signs without a JWKS-verified,
//     custody-grade, iss/aud-pinned OIDC session for that exact (iss,sub).
//   - The OIDC (iss,sub) is read from the VERIFIED session, never the body.
//   - The SA we act for is DERIVED from (iss,sub) — never client-supplied; the
//     caller can only ask us to act for the agent their session already proves.
//   - JWKS fetch failure is fail-closed (ADR-0013: no silent fallback).

import { verifyAgentSession, verifyIdToken, importJwks, type VerifyKey } from '@agenticprimitives/connect';
import { deriveSubjectSigner, type AgenticKmsConfig, type KmsBackend } from '@agenticprimitives/key-custody';
import { createKmsViemAccount } from '@agenticprimitives/key-custody/kms-viem';
import type { AuditSink } from '@agenticprimitives/audit';
import type { Address, Hex } from '@agenticprimitives/types';

export interface OidcSubject {
  iss: string;
  sub: string;
}

/**
 * Parse an `oidcFacetId` (`"<iss>#<sub>"`, e.g.
 * `"https://accounts.google.com#1234"`). `iss` is an https URL (no `#`); split
 * on the LAST `#` so a `#` in the issuer can't shift the boundary.
 */
export function parseOidcPrincipalId(id: string): OidcSubject | null {
  const at = id.lastIndexOf('#');
  if (at <= 0 || at === id.length - 1) return null;
  const iss = id.slice(0, at);
  const sub = id.slice(at + 1);
  if (!iss || !sub) return null;
  return { iss, sub };
}

/** CAIP-10 eip155 id for an address on a chain (lowercased — the canonical form). */
export function caip10(chainId: number, address: Address): string {
  return `eip155:${chainId}:${address.toLowerCase()}`;
}

/** Length-aware constant-time string compare for the server-to-server bridge secret. */
export function timingSafeEqual(a: string, b: string): boolean {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// ─── Broker JWKS (cached, fail-closed) ────────────────────────────────────

interface JwksCache {
  url: string;
  keys: VerifyKey[];
  at: number;
}
let jwksCache: JwksCache | null = null;
const JWKS_TTL_MS = 5 * 60_000;

/**
 * Fetch + cache the broker's ES256 JWKS. Throws (fail-closed) when the JWKS is
 * unreachable or malformed — the gate maps that to a 503, never a bypass.
 */
async function brokerKeys(jwksUrl: string): Promise<VerifyKey[]> {
  const now = Date.now();
  if (jwksCache && jwksCache.url === jwksUrl && now - jwksCache.at < JWKS_TTL_MS) {
    return jwksCache.keys;
  }
  const res = await fetch(jwksUrl, { headers: { accept: 'application/json' } });
  if (!res.ok) throw new Error(`broker JWKS fetch failed: HTTP ${res.status}`);
  const jwks = (await res.json()) as Parameters<typeof importJwks>[0];
  if (!jwks?.keys?.length) throw new Error('broker JWKS has no keys');
  const keys = await importJwks(jwks);
  jwksCache = { url: jwksUrl, keys, at: now };
  return keys;
}

export type GateResult =
  | { ok: true; subject: OidcSubject; sessionSub: string; rotation: number }
  | { ok: false; status: number; error: string };

export interface VerifyCustodySessionOpts {
  jwksUrl: string;
  // A predicate (or string / string[]) — the broker signs the apex AND every `<label>.<domain>` home
  // with the SAME key, so a custody session minted on a per-handle subdomain must verify here too
  // (mirrors the broker's own `ownIssuer` widening; exact-string-only 401'd cross-subdomain sessions).
  expectedIss: string | readonly string[] | ((iss: string) => boolean);
  expectedAud: string;
}

/**
 * Verify a client-supplied Google custody session against the broker JWKS and
 * enforce the custody-grade gate. On success, returns the OIDC subject read
 * from the VERIFIED session (`principal.id`) plus the session's claimed SA
 * (`sub`, CAIP-10) — the caller cross-checks the latter against the derived SA.
 */
export async function verifyCustodySession(token: string, opts: VerifyCustodySessionOpts): Promise<GateResult> {
  if (!token) return { ok: false, status: 401, error: 'missing session' };
  let keys: VerifyKey[];
  try {
    keys = await brokerKeys(opts.jwksUrl);
  } catch {
    return { ok: false, status: 503, error: 'broker JWKS unavailable (fail-closed)' };
  }
  const v = await verifyAgentSession(token, {
    keys,
    expectedIss: opts.expectedIss,
    expectedAud: opts.expectedAud,
  });
  if (!v.ok) return { ok: false, status: 401, error: `invalid session: ${v.reason}` };
  const s = v.session;
  // Custody-grade gate: only an on-chain-confirmed, custody-grade OIDC session
  // may move a member's KMS custodian (spec 235 §5 step 1).
  if (s.principal.kind !== 'oidc') return { ok: false, status: 403, error: 'session principal is not oidc' };
  if (s.principal.role !== 'custody-grade') return { ok: false, status: 403, error: 'session is not custody-grade' };
  if (s.assurance !== 'onchain-confirmed') return { ok: false, status: 403, error: 'session is not onchain-confirmed' };
  const subject = parseOidcPrincipalId(s.principal.id);
  if (!subject) return { ok: false, status: 400, error: 'malformed oidc principal id' };
  // Rotation (spec 235 §5b) is a broker-signed derivation input — derive the matching key.
  const rotation = typeof s.rotation === 'number' && s.rotation >= 0 ? s.rotation : 0;
  return { ok: true, subject, sessionSub: s.sub, rotation };
}

// ─── Per-subject custodian ─────────────────────────────────────────────────

export interface SubjectCustodian {
  /** The per-subject custodian address C_sub. */
  cSub: Address;
  /** Sign a 32-byte digest (e.g. a userOp hash) with C_sub. Returns a 65-byte
   *  EIP-191-wrapped ECDSA sig — accepted by AgentAccount._verifyEcdsa. */
  sign: (digest: Hex) => Promise<Hex>;
}

/**
 * Derive the per-subject custodian for a verified OIDC subject. `masterHex` is
 * `A2A_MASTER_PRIVATE_KEY` from the Worker env (passed explicitly — Workers
 * don't populate `process.env` for the master). The production guard on
 * `LocalSecp256k1Signer` still applies (refuses NODE_ENV=production unless
 * `A2A_ALLOW_LOCAL_MASTER_KEY=true`).
 */
export async function deriveSubjectCustodian(
  subject: OidcSubject,
  /** The in-process derivation master. Meaningful ONLY for local derivation — under `agentic-kms` the
   *  master lives in AKCS and never enters this process, so callers there pass nothing. */
  masterHex: string | undefined,
  opts: { backend?: KmsBackend; auditSink?: AuditSink; rotation?: number; agenticKms?: AgenticKmsConfig } = {},
): Promise<SubjectCustodian> {
  const backend = opts.backend ?? 'local-aes';
  // Fail closed and say which value is missing. A local backend without a master cannot derive anything,
  // and defaulting one would mint custody keys from a value nobody chose.
  if (backend !== 'agentic-kms' && !masterHex) {
    throw new Error(
      `[demo-a2a] custody derivation on "${backend}" requires A2A_CUSTODY_ROOT_KEY. It is optional only ` +
        'under agentic-kms, where AKCS derives C_sub from the tenant signing seed (ADR-0013: no fallback).',
    );
  }
  // agentic-kms: the master never enters this process — AKCS derives C_sub from the tenant signing
  // seed (the legacy master imported via ceremony) with the identical v1 scheme. No fallback.
  const signerBackend = deriveSubjectSigner({
    subject: { iss: subject.iss, sub: subject.sub, rotation: opts.rotation },
    backend,
    ...(backend === 'agentic-kms' ? { agenticKms: opts.agenticKms } : { config: { derivationSecretHex: masterHex! } }),
    auditSink: opts.auditSink, // G-2: every C_sub signature emits key-custody.sign
  });
  const acct = await createKmsViemAccount(signerBackend);
  return {
    cSub: acct.address,
    sign: async (digest) => (await acct.signMessage({ message: { raw: digest } })) as Hex,
  };
}

/** GENERAL Home-session verification (spec 322 W2 — the interaction skills' caller gate): any
 *  principal kind (passkey / oidc / wallet), broker-JWKS-verified. Returns the session's SA.
 *  Distinct from verifyCustodySession, which additionally enforces the custody-grade OIDC gate. */
export async function verifyHomeSession(
  token: string,
  env: { BROKER_JWKS_URL?: string; BROKER_ISS?: string; DEMO_SSO_AUD?: string },
): Promise<{ ok: true; sa: Address; caip: string; principal?: { kind: string; id: string } } | { ok: false; status: number; error: string }> {
  if (!env.BROKER_JWKS_URL || !env.BROKER_ISS || !env.DEMO_SSO_AUD) return { ok: false, status: 503, error: 'broker gate not configured' };
  if (!token) return { ok: false, status: 401, error: 'missing session' };
  let keys: VerifyKey[];
  try {
    keys = await brokerKeys(env.BROKER_JWKS_URL);
  } catch {
    return { ok: false, status: 503, error: 'broker JWKS unavailable (fail-closed)' };
  }
  // Accept the broker apex AND any single-label `<handle>.<registrable-domain>` home origin (spec 232):
  // the broker signs them all with the same key, so a session minted on a per-handle subdomain must
  // verify here too. Derive the REGISTRABLE DOMAIN (last two labels) from BROKER_ISS — NOT its full
  // hostname. Using the full host (e.g. `www.impact-agent.me`) made every `<handle>.impact-agent.me`
  // session 401 with "iss mismatch" on record.get/put (profile + channels broken on the subdomain home).
  // Mirrors ownConnectIssuer() in index.ts.
  const issRaw = env.BROKER_ISS.replace(/\/$/, '');
  let base = issRaw.replace(/^https?:\/\//, '').toLowerCase();
  try {
    const parts = new URL(issRaw).hostname.toLowerCase().split('.');
    base = parts.length >= 2 ? parts.slice(-2).join('.') : parts.join('.');
  } catch { /* keep the stripped host */ }
  const issOk = (v: string): boolean => {
    try {
      const h = new URL(v).hostname.toLowerCase();
      return h === base || (h.endsWith('.' + base) && /^[a-z0-9-]+$/.test(h.slice(0, -(base.length + 1))));
    } catch { return false; }
  };
  const v = await verifyAgentSession(token, { keys, expectedIss: issOk, expectedAud: env.DEMO_SSO_AUD });
  if (!v.ok) return { ok: false, status: 401, error: `invalid session: ${v.reason}` };
  const sa = v.session.sub.match(/0x[0-9a-fA-F]{40}$/)?.[0] as Address | undefined;
  if (!sa) return { ok: false, status: 400, error: 'no SA in session sub' };
  // The sign-in identity behind the session (e.g. `{kind:'oidc', id:'email#<sha256>'}` for an email sign-in), for an
  // op that must bind a record to what the person proved: the operator directory records only the address whose hash
  // the session carries (operator-directory.ts, 2026-10-23).
  const p = (v.session as { principal?: { kind?: unknown; id?: unknown } }).principal;
  const principal = p && typeof p.kind === 'string' && typeof p.id === 'string' ? { kind: p.kind, id: p.id } : undefined;
  return { ok: true, sa, caip: v.session.sub, ...(principal ? { principal } : {}) };
}

/** Verify a REGISTERED relying app's OIDC id_token (e.g. the uupg tracker driving the org's discussion
 *  board over the standard a2a path). The Home mints these with `aud=<client_id>` — NOT `DEMO_SSO_AUD`
 *  — so `verifyHomeSession` rejects them. Here the SIGNATURE against the Home JWKS + the issuer-is-this-
 *  Home check are the real proof of identity; `aud` is a client_id (accepted as-is, since AUTHORIZATION
 *  is enforced downstream on-chain by the steward/member gate — the token only asserts *who* the person
 *  is, and can only ever act as that person). Same registrable-domain issuer rule as sessions. */
export async function verifyRelyingIdToken(
  token: string,
  env: { BROKER_JWKS_URL?: string; BROKER_ISS?: string },
  // spec 341 §4.3 — `clientId` is the VERIFIED `aud`: which relying app is calling. It was already
  // verified here (`expectedAud`) and then thrown away, which is why per-app anything was impossible.
  // It is the key a per-app read grant is stored and revoked under; without it every app is
  // indistinguishable at the gate and revocation can only be all-or-nothing.
): Promise<{ ok: true; sa: Address; caip: string; clientId: string } | { ok: false; status: number; error: string }> {
  if (!env.BROKER_JWKS_URL || !env.BROKER_ISS) return { ok: false, status: 503, error: 'broker gate not configured' };
  if (!token) return { ok: false, status: 401, error: 'missing session' };
  let keys: VerifyKey[];
  try {
    keys = await brokerKeys(env.BROKER_JWKS_URL);
  } catch {
    return { ok: false, status: 503, error: 'broker JWKS unavailable (fail-closed)' };
  }
  // Peek iss + aud (unverified), gate iss to THIS Home, THEN verify sig/iss/aud/exp against those values.
  let iss: string | undefined, aud: string | undefined;
  try {
    const payload = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob((token.split('.')[1] ?? '').replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0)))) as { iss?: string; aud?: string };
    iss = typeof payload.iss === 'string' ? payload.iss : undefined;
    aud = typeof payload.aud === 'string' ? payload.aud : undefined;
  } catch {
    return { ok: false, status: 401, error: 'unparseable id_token' };
  }
  const issRaw = env.BROKER_ISS.replace(/\/$/, '');
  let base = issRaw.replace(/^https?:\/\//, '').toLowerCase();
  try {
    const parts = new URL(issRaw).hostname.toLowerCase().split('.');
    base = parts.length >= 2 ? parts.slice(-2).join('.') : parts.join('.');
  } catch { /* keep stripped host */ }
  const issOk = (v?: string): boolean => {
    if (!v) return false;
    try {
      const h = new URL(v).hostname.toLowerCase();
      return h === base || (h.endsWith('.' + base) && /^[a-z0-9-]+$/.test(h.slice(0, -(base.length + 1))));
    } catch { return false; }
  };
  if (!issOk(iss) || !aud) return { ok: false, status: 401, error: 'id_token iss/aud not accepted' };
  const r = await verifyIdToken(token, { keys, expectedIss: iss!, expectedAud: aud });
  if (!r.ok) return { ok: false, status: 401, error: `invalid id_token: ${r.reason}` };
  const sub = (r.claims.canonical_agent_id ?? r.claims.sub ?? '') as string;
  const sa = sub.match(/0x[0-9a-fA-F]{40}$/)?.[0] as Address | undefined;
  if (!sa) return { ok: false, status: 400, error: 'no SA in id_token sub' };
  return { ok: true, sa, caip: sub, clientId: aud! };
}
