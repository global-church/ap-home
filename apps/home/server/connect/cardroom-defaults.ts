// POST /connect/cardroom-defaults — finish the card room's arrangement for a DEMO person, server-side.
//
// A person who connects to the card room through the browser gets the app's defaults applied in the connect
// ceremony (`src/lib/client-defaults.ts`: the skills on the agent, the playbook's specialist line, the study
// grant the person signs). A DEMO persona connects to the card room through `/connect/demo-signin` — a
// server-to-server sign-in with no ceremony page — so nothing ran for them. This route runs the same three
// acts for a demo persona, signing with the seeded custodian this Home holds for them; for anyone else it
// answers `needsSignature` and the card room points them at Settings → Coaches, where they sign.
//
// Gates, fail-closed: a valid Home session; the acts are ALWAYS for the SA in that session's own `sub`.
// Idempotent: what is already there is left alone. Nothing here widens authority — the grant is the bounded
// study grant the Coaches page issues, and the person can fire the coach there.
import { importJwks, verifyAgentSession } from '@agenticprimitives/connect';
import { AgentNamingClient } from '@agenticprimitives/agent-naming';
import { agentProfileResolverAbi, buildRegisterProfileCall } from '@agenticprimitives/agent-profile';
import { buildExecuteBatchCallData } from '@agenticprimitives/agent-account';
import { buildCaveat, buildVaultRecordScopeCaveat, encodeTimestampTerms, hashDelegation, ROOT_AUTHORITY, type Delegation } from '@agenticprimitives/delegation';
import { definitionDigest, validateAgentHarnessDefinition, type AgentHarnessDefinitionV1 } from '@agenticprimitives/capability-claims';
import type { Address, Hex } from '@agenticprimitives/types';
import { createPublicClient, encodeFunctionData, http, keccak256, toBytes } from 'viem';
import { getServer, ownIssuer, resolveOrigin, type FnContext } from '../_lib/server-broker';
import { demoPersonaFor, signDigestAsDemoPersona } from '../_lib/demo-custody';
import { callInteractions } from './channels';
import { CHAIN, CHAIN_ID, CONTRACTS, DEFAULT_RPC_URL } from '../../src/lib/chain';
import { SKILLS_REGISTRY_ORIGIN } from '../../src/lib/domain';
import { isAllowedClientOrigin } from '../../src/lib/oidc-clients';
import { CLIENT_DEFAULTS } from '../../src/lib/client-defaults';
import { GAMES, STUDY_GRANT_DAYS, STUDY_SERVER, coachFor, studyScopesFor } from '../../src/lib/coaches';

function cors(request: Request): Record<string, string> {
  const origin = request.headers.get('Origin') ?? '';
  return origin && isAllowedClientOrigin(origin)
    ? { 'access-control-allow-origin': origin, 'access-control-allow-headers': 'authorization, content-type', 'access-control-allow-methods': 'POST, OPTIONS', vary: 'Origin' }
    : {};
}
const json = (b: unknown, request: Request, s = 200): Response =>
  new Response(JSON.stringify(b), { status: s, headers: { 'content-type': 'application/json', ...cors(request) } });

export const onRequestOptions = async ({ request }: FnContext): Promise<Response> => new Response(null, { status: 204, headers: cors(request) });

const ATL_CAPABILITIES: Hex = keccak256(toBytes('atl:capabilities'));

export const onRequestPost = async ({ request, env }: FnContext): Promise<Response> => {
  const auth = request.headers.get('authorization') ?? '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  if (!token) return json({ error: 'session required' }, request, 401);
  const { jwks } = await getServer(env);
  const keys = await importJwks(jwks);
  const v = await verifyAgentSession(token, { keys, expectedAud: env.DEMO_SSO_AUD ?? 'demo-sso', expectedIss: ownIssuer(request, env) });
  if (!v.ok) return json({ error: 'invalid session' }, request, 401);
  const person = (v.session.sub.match(/0x[0-9a-fA-F]{40}$/)?.[0] ?? '').toLowerCase() as Address;
  if (!person) return json({ error: 'no agent in session' }, request, 400);
  const body = (await request.json().catch(() => ({}))) as { client_id?: string };
  const clientId = String(body.client_id ?? 'pokernight');
  const d = CLIENT_DEFAULTS[clientId];
  if (!d) return json({ ok: true, applied: [], skipped: ['no defaults for this app'] }, request);
  const persona = demoPersonaFor(env, person);
  if (!persona) return json({ ok: false, needsSignature: true, error: 'not a demo person — sign at the Home under Settings → Coaches' }, request);
  const a2a = (env as { A2A_CUSTODY_URL?: string }).A2A_CUSTODY_URL?.replace(/\/$/, '');
  if (!a2a) return json({ error: 'interactions execution point not configured' }, request, 503);
  const games = d.coaches.map((c) => ({ service: c.service, game: GAMES.find((g) => g.id === c.game)! })).filter((c) => c.game);
  const applied: string[] = []; const skipped: string[] = [];
  const sign = (digest: Hex) => signDigestAsDemoPersona(persona, digest);
  const rpcUrl = ((env as { RPC_URL?: string }).RPC_URL || DEFAULT_RPC_URL);
  const pc = createPublicClient({ chain: CHAIN, transport: http(rpcUrl) });

  try {
    // 1. The card room's skills on the agent (atl:capabilities), one sponsored userOp signed by the custodian.
    const current = String(await pc.readContract({ address: CONTRACTS.agentProfileResolver, abi: agentProfileResolverAbi, functionName: 'getStringProperty', args: [person, ATL_CAPABILITIES] }).catch(() => ''));
    const have = current.split(',').map((s) => s.trim()).filter(Boolean);
    const want = [...new Set(games.flatMap((c) => c.game.agentCapabilities.map((x) => x.capabilityId!)))].filter((id) => !have.includes(id));
    if (want.length === 0) skipped.push('skills');
    else {
      const registered = (await pc.readContract({ address: CONTRACTS.agentProfileResolver, abi: agentProfileResolverAbi, functionName: 'isRegistered', args: [person] }).catch(() => false)) as boolean;
      const calls = [
        ...(registered ? [] : [buildRegisterProfileCall({ profileResolver: CONTRACTS.agentProfileResolver, agent: person, displayName: (persona.name ?? 'agent').split('.')[0] ?? 'agent' })]),
        { to: CONTRACTS.agentProfileResolver, value: 0n, data: encodeFunctionData({ abi: agentProfileResolverAbi, functionName: 'setStringProperty', args: [person, ATL_CAPABILITIES, [...have, ...want].join(',')] }) },
      ];
      const callData = buildExecuteBatchCallData(calls);
      // The account routes take a CSRF pair like every mutating /a2a call (the scripts fetch it the same way).
      const origin = resolveOrigin(request, env);
      const csrfRes = await fetch(`${a2a}/auth/csrf`, { headers: { origin } });
      const csrf = (await csrfRes.json().catch(() => ({}))) as { token?: string };
      const H = { 'content-type': 'application/json', origin, cookie: (csrfRes.headers.get('set-cookie') ?? '').split(';')[0] ?? '', 'x-csrf-token': csrf.token ?? '' };
      const built = (await (await fetch(`${a2a}/account/build-call-userop`, { method: 'POST', headers: H, body: JSON.stringify({ sender: person, callData }) })).json().catch(() => ({}))) as { ok?: boolean; userOp?: Record<string, unknown>; userOpHash?: Hex; error?: string; detail?: string };
      if (!built.ok || !built.userOpHash) throw new Error(`skills: ${built.error ?? 'could not build the userOp'}${built.detail ? ` — ${String(built.detail).slice(0, 120)}` : ''}`);
      const sent = (await (await fetch(`${a2a}/account/submit-call-userop`, { method: 'POST', headers: H, body: JSON.stringify({ userOp: { ...built.userOp, signature: await sign(built.userOpHash) } }) })).json().catch(() => ({}))) as { ok?: boolean; error?: string };
      if (!sent.ok) throw new Error(`skills: ${sent.error ?? 'the userOp was not accepted'}`);
      applied.push('skills');
    }

    // 2. A playbook (the person steward's, when none is assigned), then the specialist lines.
    const got = await callInteractions(env, person, 'channels.archetypeAssignment.get', { session: token });
    let rec = (got.body.record ?? null) as { type: string; archetypeId: string; archetypeVersion: string; definitionDigest: string; definition: AgentHarnessDefinitionV1 } | null;
    if (!rec?.definition) {
      if (!SKILLS_REGISTRY_ORIGIN) throw new Error('playbook: this Home has no skills registry');
      const r = await fetch(`${SKILLS_REGISTRY_ORIGIN.replace(/\/$/, '')}/context/contexts/agentic-trust/archetypes/person-steward/definition`, { headers: { 'user-agent': 'Mozilla/5.0 (cardroom-defaults)' } });
      const b = (await r.json().catch(() => ({}))) as { definition?: AgentHarnessDefinitionV1; digest?: string };
      if (!b.definition || !b.digest || !validateAgentHarnessDefinition(b.definition).ok) throw new Error('playbook: the person-steward definition could not be read');
      rec = { type: 'ap.archetype-assignment.v1', archetypeId: b.definition.archetypeId, archetypeVersion: b.definition.archetypeVersion, definitionDigest: b.digest, definition: b.definition };
      const put = await callInteractions(env, person, 'channels.archetypeAssignment.put', { session: token, record: rec });
      if (put.body.ok !== true) throw new Error(`playbook: ${String(put.body.error ?? 'not assigned')}`);
      applied.push('playbook');
    }
    // ONE COACH PER GAME, every specialist line written in one put.
    let specialists = rec.definition.specialists ?? [];
    let changed = false;
    for (const { game, service } of games) {
      if (coachFor(specialists, game) === service) { skipped.push(`specialist:${game.id}`); continue; }
      specialists = [...specialists.filter((s) => !game.coached.includes(s.capability)), ...game.coached.map((capability) => ({ capability, executor: service }))];
      changed = true;
      applied.push(`specialist:${game.id}`);
    }
    if (changed) {
      const definition: AgentHarnessDefinitionV1 = { ...rec.definition, specialists };
      const check = validateAgentHarnessDefinition(definition);
      if (!check.ok) throw new Error(`playbook: ${check.errors[0]}`);
      const put = await callInteractions(env, person, 'channels.archetypeAssignment.put', { session: token, record: { ...rec, definition, definitionDigest: definitionDigest(definition) } });
      if (put.body.ok !== true) throw new Error(`playbook: ${String(put.body.error ?? 'not written')}`);
    }

    // 3. The study grants — one per game's coach, scoped to THAT game's cabinet — unless a live one is stored.
    const listed = await callInteractions(env, person, 'studygrant.list', { session: token });
    const grants = (listed.body.grants ?? []) as Array<{ coach: string; revoked: boolean; resources?: string[] }>;
    const naming = new AgentNamingClient({ rpcUrl, chainId: CHAIN_ID, registry: CONTRACTS.agentNameRegistry, universalResolver: CONTRACTS.agentNameUniversalResolver });
    for (const { game, service } of games) {
      const scopes = studyScopesFor(game.id);
      if (grants.some((g) => g.coach === service && !g.revoked && (g.resources ?? []).some((r) => scopes.reads.includes(r)))) { skipped.push(`grant:${game.id}`); continue; }
      const coachSA = (await naming.resolveName(service).catch(() => null)) as Address | null;
      if (!coachSA) throw new Error(`grant: ${service} does not resolve`);
      const nowSec = Math.floor(Date.now() / 1000);
      const bytes = crypto.getRandomValues(new Uint8Array(16));
      let salt = 0n; for (const b of bytes) salt = (salt << 8n) | BigInt(b);
      const delegation: Delegation = {
        delegator: person, delegate: coachSA, authority: ROOT_AUTHORITY,
        caveats: [
          buildCaveat(CONTRACTS.timestampEnforcer, encodeTimestampTerms(0, nowSec + STUDY_GRANT_DAYS * 86_400)),
          buildVaultRecordScopeCaveat([{ server: STUDY_SERVER, resources: scopes.reads, ops: ['read'] }, { server: STUDY_SERVER, resources: scopes.appends, ops: ['write'] }]),
        ],
        salt, signature: '0x',
      };
      delegation.signature = await sign(hashDelegation(delegation, CHAIN_ID, CONTRACTS.delegationManager));
      const put = await callInteractions(env, person, 'studygrant.put', { session: token, coach: service, delegation: { ...delegation, salt: salt.toString() } });
      if (put.body.ok !== true) throw new Error(`grant: ${String(put.body.error ?? 'not stored')}`);
      applied.push(`grant:${game.id}`);
    }
    return json({ ok: true, coaches: games.map((c) => ({ game: c.game.id, coach: c.service })), applied, skipped }, request);
  } catch (e) {
    return json({ ok: false, error: e instanceof Error ? e.message : String(e), applied, skipped }, request, 500);
  }
};
