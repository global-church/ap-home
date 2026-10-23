// POST /connect/email/verify — verify the emailed code, then one of three outcomes:
//   • Bearer session present  → LINK: record the email facet for that signed-in agent (add email as a
//     login method; same security model as the Google link path — a custody/login session authorizes it).
//   • email facet exists      → ISSUE a login-grade session (asserted; email is never custody-grade).
//   • no facet                → BOOTSTRAP (a new person home needs to be created; client onboards).
// The OTP record is keyed by SHA-256(email); the code is checked with bounded attempts (anti-brute-force).
import { getServer, resolveOrigin, ownIssuer, type FnContext } from '../_lib/server-broker';
import { mintAgentSession, importJwks, verifyAgentSession } from '@agenticprimitives/connect';
import { readEmailFacet, recordEmailFacet, emailHash, readRotation } from '../../src/lib/kv-indexer';
import { isTestEmail, markTestAgent } from '../../src/lib/test-identity';
import { resolveKmsAgent } from '../_lib/kms-resolve';
import { isSocialCustodyAud } from '../../src/lib/oidc-clients';
import { oidcFacetId } from '@agenticprimitives/connect-auth/google';
import type { CredentialPrincipal, CanonicalAgentId } from '@agenticprimitives/types';
import { recordContactEmail } from '../_lib/contact-directory';
import { operatorOrg, recordVerifiedEmail } from '../_lib/operator-directory';

// The (iss, sub) namespace for email-subject KMS custody. Email has no OIDC provider, so WE are the
// issuer authority: `iss = 'email'`, `sub = SHA-256(email)`. demo-a2a derives the per-subject custodian
// C_sub from exactly this pair (spec 235 §5, provider-neutral OIDC-subject custody) — the SAME mechanism
// Google uses, so the custody session is minted OIDC-shaped (`kind:'oidc'`, `id = 'email#<hash>'`).
const EMAIL_ISS = 'email';

const cors = { 'access-control-allow-origin': '*', 'access-control-allow-headers': 'content-type, authorization' };
const json = (b: unknown, s = 200): Response =>
  new Response(JSON.stringify(b), { status: s, headers: { 'content-type': 'application/json', ...cors } });

export const onRequestOptions = async (): Promise<Response> => new Response(null, { status: 204, headers: cors });

const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
const MAX_ATTEMPTS = 5;

/** Resolve a signed-in session principal (person SA) from the Bearer, or null (anonymous verify). */
async function sessionAgent(request: Request, env: FnContext['env']): Promise<CanonicalAgentId | null> {
  const auth = request.headers.get('authorization') ?? '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  if (!token) return null;
  const { jwks } = await getServer(env);
  const keys = await importJwks(jwks);
  const v = await verifyAgentSession(token, { keys, expectedAud: env.DEMO_SSO_AUD ?? 'demo-sso', expectedIss: ownIssuer(request, env) });
  return v.ok ? (v.session.sub as CanonicalAgentId) : null;
}

export const onRequestPost = async ({ request, env }: FnContext): Promise<Response> => {
  const body = (await request.json().catch(() => null)) as { email?: string; otp?: string } | null;
  const email = (body?.email ?? '').trim().toLowerCase();
  const otp = (body?.otp ?? '').trim();
  if (!EMAIL_RE.test(email) || !/^\d{6}$/.test(otp)) return json({ error: 'email + 6-digit code required' }, 400);

  const hash = await emailHash(email);
  const key = `emailotp:${hash}`;
  const raw = await env.AUTH_CODES.get(key);
  if (!raw) return json({ error: 'code expired — request a new one' }, 400);
  const rec = JSON.parse(raw) as { code: string; aud: string; attempts: number };

  if (rec.code !== otp) {
    const attempts = (rec.attempts ?? 0) + 1;
    if (attempts >= MAX_ATTEMPTS) {
      await env.AUTH_CODES.delete(key);
      return json({ error: 'too many attempts — request a new code' }, 429);
    }
    await env.AUTH_CODES.put(key, JSON.stringify({ ...rec, attempts }), { expirationTtl: 600 });
    return json({ error: 'incorrect code' }, 400);
  }
  await env.AUTH_CODES.delete(key); // single-use — consumed on the first correct code

  // LINK: a signed-in user is adding email as a login method → record the facet for THEIR agent.
  const signedIn = await sessionAgent(request, env);
  if (signedIn) {
    await recordEmailFacet(env.AUTH_CODES, email, signedIn);
    // The operator's copy of a verified contact address (contact-directory.ts). Never fails the link.
    // The verified address goes to the operator directory when it is configured (2026-10-23), else the KV copy as before.
    await (operatorOrg(env) ? recordVerifiedEmail(env, request, String(signedIn), email) : recordContactEmail(env, String(signedIn), email, 'email-link'));
    return json({ status: 'linked', via: 'email' });
  }

  // ── ANONYMOUS: ISSUE (known home) or BOOTSTRAP (create a KMS-custodied home). ──
  // Email is a login-grade credential, but — exactly like Google × KMS on the Personal Home (spec 235) — an
  // email with no home of its OWN gets a per-subject KMS-custodied home (iss='email', sub=SHA-256(email)).
  // The OTP we just verified is the authn; demo-a2a derives + holds C_sub (G-1, testnet-acceptable custody).
  // The email FACET stays login-grade/asserted (enroll still rejects `kind:'email'`); it's the KMS custodian
  // C_sub — not the email — that confers on-chain authority, so this is not "email as a custodian".
  const iss = resolveOrigin(request, env);
  const { signer } = await getServer(env);
  const custodyAud = env.DEMO_SSO_AUD ?? 'demo-sso';

  const facet = await readEmailFacet(env.AUTH_CODES, email); // a prior email-home OR a linked device home
  // KMS custody is offered for the Personal-Home aud (+ socialCustody clients, spec 294); other auds stay
  // login-grade — their members onboard through the Personal Home.
  const custodyEligible = isSocialCustodyAud(rec.aud, custodyAud);
  const rotation = await readRotation(env.AUTH_CODES, EMAIL_ISS, hash);
  let kms = custodyEligible
    ? await resolveKmsAgent(env, EMAIL_ISS, hash, rotation)
    : ({ ok: false, reason: 'aud not custody-eligible' } as const);
  // A transient resolve failure must NOT silently demote a returning custody-grade user to a
  // login-grade session — that session later 403s at demo-a2a's custody sign gate mid-connect
  // ("session principal is not oidc"), a far worse failure than asking for the code again.
  if (custodyEligible && !kms.ok) {
    kms = await resolveKmsAgent(env, EMAIL_ISS, hash, rotation); // one retry
    if (!kms.ok && facet) {
      console.error('[email-verify] KMS resolve failed for a custody-eligible subject with a facet — refusing to demote', { reason: kms.reason, facet });
      return json({ error: 'custody service temporarily unavailable — request a new code and try again' }, 503);
    }
  }

  let agent: CanonicalAgentId;
  let custodyGrade: boolean;
  if (kms.ok && (!facet || facet.toLowerCase() === kms.agentId.toLowerCase())) {
    // The email's OWN KMS home — a fresh bootstrap OR a returning visit (the SA is deterministic; the client
    // deploys it on-chain via secureHomeNoName if it isn't yet). Refresh the facet (idempotent; tracks
    // rotation). Custody-grade: C_sub is a real on-chain custodian, re-verified by demo-a2a's gate.
    await recordEmailFacet(env.AUTH_CODES, email, kms.agentId);
    agent = kms.agentId;
    custodyGrade = true;
    // A test identity (name+gcidtest@…, src/lib/test-identity.ts) is marked here, the one moment the address is in
    // hand, so the Admin counts can leave it out. Only for the email's OWN home: a real home that merely LINKED a
    // tagged address (the branch below) is a real person. A failed mark never fails a sign-in.
    if (isTestEmail(email)) {
      await markTestAgent(env.AUTH_CODES, String(kms.agentId)).catch((e: unknown) => console.warn('[email-verify] test mark failed', e));
    }
  } else if (facet) {
    // Email was LINKED to another home (e.g. a passkey home, via the Security card). Respect the link:
    // issue a login-grade session — email never confers custody OVER a device-secured home (ADR-0011).
    // Diagnosable demotion: this session CANNOT authorize a connect via the KMS signer (403 at the
    // custody gate) — the member signs such approvals with the home's real credential.
    console.warn('[email-verify] login-grade session (facet-linked home)', { facet, kmsOk: kms.ok, kmsAgent: kms.ok ? kms.agentId : null, reason: kms.ok ? 'facet != kms home' : (kms as { reason?: string }).reason });
    agent = facet;
    custodyGrade = false;
  } else {
    // No home + custody ineligible/unreachable → the client onboards with a passkey/Google first.
    return json({ status: 'bootstrap', via: 'email', email });
  }

  // The operator's copy of the address this person just verified (contact-directory.ts, 2026-10-21): every account
  // from launch on can be reached. Encrypted; Admin-only; never fails a sign-in.
  await (operatorOrg(env) ? recordVerifiedEmail(env, request, String(agent), email) : recordContactEmail(env, String(agent), email, 'email-sign-in'));

  const sessionPrincipal: CredentialPrincipal = custodyGrade
    // Custody sessions are OIDC-subject-shaped (`kind:'oidc'`, id='email#<hash>') so demo-a2a's provider-
    // neutral custody gate re-derives C_sub — the email origin stays visible in the subject `iss`.
    ? { kind: 'oidc', id: oidcFacetId(EMAIL_ISS, hash), assurance: 'onchain-confirmed', role: 'custody-grade' }
    : { kind: 'email', id: hash, assurance: 'asserted', role: 'login-grade' };
  const token = await mintAgentSession(
    {
      sub: agent,
      principal: sessionPrincipal,
      // Custody-grade = home-level authority → the home/custody aud demo-a2a's `/custody` gate verifies,
      // carrying the rotation so it derives the matching per-subject key (spec 235 §5b). Login-grade stays
      // bound to the requesting aud.
      assurance: custodyGrade ? 'onchain-confirmed' : 'asserted',
      aud: custodyGrade ? custodyAud : rec.aud,
      iss,
      ttlSeconds: 3600,
      ...(custodyGrade ? { rotation } : {}),
    },
    signer,
  );
  // `custody:true` tells the client to secure the home on-chain (secureHomeNoName) before proceeding — a
  // fresh KMS home isn't deployed until then. For a linked device home it's already secured.
  return json({ status: 'issued', token, via: 'email', custody: custodyGrade });
};
