// CO-MANAGERS: make another person a manager (steward) of an organization, and optionally a co-custodian
// (Global.Church, 2026-10-23 — the operator org is held by Ryan and Paul; gc-estate/docs/operator-workspace.md).
//
//   POST /connect/co-manager            {action:'offer', org, person, delegation}   a manager offers stewardship
//   POST /connect/co-manager            {action:'accept', org, custodian?}           the person accepts, as themselves
//   GET  /connect/co-manager            the signed-in person's offers to them
//   GET  /connect/co-manager?org=<org>  a manager's view of the org's offers (with whether each custodian was added)
//
// The authority is the STEWARDSHIP DELEGATION itself: org → person, signed as the org by a current manager, verified
// on-chain (signature, window, not revoked) when offered and again when accepted. Accepting writes the person's own link
// to the org, which is what every steward check reads (and re-verifies). Revoking is the ordinary on-chain revoke.
// Co-custody is separate and on-chain: the accepting person names their custodian address; this checks it really
// controls their account (`isCustodian`); a current manager then adds it to the org with `addCustodian` from the
// org's page. Nothing here stores a key.
import { createPublicClient, http } from 'viem';
import type { FnContext, KVNamespace } from '../_lib/server-broker';
import { callerFromInviteAuth, stewardControl } from './org-invite';
import { verifyStewardship } from '../_lib/verify-stewardship';
import type { IncomingDelegation } from '../_lib/verify-delegation';
import { DEFAULT_RPC_URL } from '../../src/lib/chain';

const json = (b: unknown, s = 200): Response =>
  new Response(JSON.stringify(b), { status: s, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });
const ADDRESS = /^0x[0-9a-f]{40}$/;
const offerKey = (person: string, org: string) => `co-manager:${person}:${org}`;
const orgIndex = (org: string) => `co-manager-idx:${org}`;
/** A pending offer lives 30 days; once accepted the grant is dropped from it (it then lives in the person's link). */
const OFFER_TTL_S = 30 * 24 * 60 * 60;

const IS_CUSTODIAN_ABI = [
  { type: 'function', name: 'isCustodian', stateMutability: 'view', inputs: [{ name: 'a', type: 'address' }], outputs: [{ name: '', type: 'bool' }] },
] as const;

export interface CoManagerOffer {
  org: string;
  person: string;
  orgName: string;
  offeredBy: string;
  offeredAt: number;
  /** Present only while pending. */
  delegation?: IncomingDelegation;
  acceptedAt?: number;
  /** The accepting person's custodian, verified to control their account; a manager adds it to the org. */
  custodian?: string;
}

async function isCustodian(env: { RPC_URL?: string }, account: string, who: string): Promise<boolean> {
  try {
    const c = createPublicClient({ transport: http(env.RPC_URL || DEFAULT_RPC_URL) });
    return (await c.readContract({ address: account as `0x${string}`, abi: IS_CUSTODIAN_ABI, functionName: 'isCustodian', args: [who as `0x${string}`] })) as boolean;
  } catch {
    return false;
  }
}

async function readJson<T>(kv: KVNamespace, key: string): Promise<T | null> {
  try { const raw = await kv.get(key); return raw ? (JSON.parse(raw) as T) : null; } catch { return null; }
}

export const onCoManagerGet = async ({ request, env }: FnContext): Promise<Response> => {
  const org = (new URL(request.url).searchParams.get('org') ?? '').toLowerCase();
  if (org) {
    if (!ADDRESS.test(org)) return json({ error: 'bad org' }, 400);
    const ctl = await stewardControl(env, request, org);
    if (!ctl) return json({ error: 'only someone who manages this organization can see its co-manager offers' }, 403);
    const people = (await readJson<string[]>(env.AUTH_CODES, orgIndex(org))) ?? [];
    const offers = (await Promise.all(people.map((p) => readJson<CoManagerOffer>(env.AUTH_CODES, offerKey(p, org))))).filter((o): o is CoManagerOffer => !!o);
    const out = await Promise.all(offers.map(async ({ delegation: _d, ...o }) => ({
      ...o,
      custodianAdded: o.custodian ? await isCustodian(env, org, o.custodian) : false,
    })));
    return json({ ok: true, offers: out });
  }
  const caller = await callerFromInviteAuth(env, request);
  if (!caller) return json({ error: 'sign in first' }, 401);
  const keys: string[] = [];
  let cursor: string | undefined;
  for (let i = 0; i < 20; i++) {
    const page = await env.AUTH_CODES.list({ prefix: `co-manager:${caller.person}:`, ...(cursor ? { cursor } : {}), limit: 100 });
    keys.push(...page.keys.map((k) => k.name));
    if (page.list_complete || !page.cursor) break;
    cursor = page.cursor;
  }
  const offers = (await Promise.all(keys.map((k) => readJson<CoManagerOffer>(env.AUTH_CODES, k)))).filter((o): o is CoManagerOffer => !!o && !o.acceptedAt);
  return json({ ok: true, offers: offers.map(({ delegation: _d, ...o }) => o) });
};

export const onCoManagerPost = async ({ request, env }: FnContext): Promise<Response> => {
  const body = (await request.json().catch(() => ({}))) as { action?: string; org?: string; person?: string; delegation?: IncomingDelegation; custodian?: string; orgName?: string };
  const org = String(body.org ?? '').toLowerCase();
  if (!ADDRESS.test(org)) return json({ error: 'org must be an organization address' }, 400);

  if (body.action === 'offer') {
    const ctl = await stewardControl(env, request, org);
    if (!ctl) return json({ error: 'only someone who manages this organization can offer co-management' }, 403);
    const person = String(body.person ?? '').toLowerCase();
    if (!ADDRESS.test(person) || person === org) return json({ error: 'person must be a GCID account address' }, 400);
    if (person === ctl.person) return json({ error: 'you already manage this organization' }, 400);
    // The offered grant must already BE stewardship of this org for that person, signed as the org.
    if (!(await verifyStewardship(env, org, person, body.delegation))) {
      return json({ error: 'the grant is not a valid stewardship of this organization for that person' }, 400);
    }
    const link = await readJson<{ orgName?: string; displayName?: string }>(env.AUTH_CODES, `related:${ctl.person}:${org}`);
    const offer: CoManagerOffer = {
      org, person, orgName: link?.displayName || link?.orgName || org,
      offeredBy: ctl.person, offeredAt: Date.now(), delegation: body.delegation!,
    };
    await env.AUTH_CODES.put(offerKey(person, org), JSON.stringify(offer), { expirationTtl: OFFER_TTL_S });
    const idx = (await readJson<string[]>(env.AUTH_CODES, orgIndex(org))) ?? [];
    if (!idx.includes(person)) await env.AUTH_CODES.put(orgIndex(org), JSON.stringify([...idx, person]));
    console.info('[co-manager] offered', { org, person, by: ctl.person });
    return json({ ok: true });
  }

  if (body.action === 'accept') {
    const caller = await callerFromInviteAuth(env, request);
    if (!caller) return json({ error: 'sign in first' }, 401);
    const person = caller.person;
    const offer = await readJson<CoManagerOffer>(env.AUTH_CODES, offerKey(person, org));
    if (!offer || !offer.delegation) return json({ error: 'no pending co-manager offer for you from this organization' }, 404);
    // Re-verified at acceptance: an offer revoked since it was made is refused.
    if (!(await verifyStewardship(env, org, person, offer.delegation))) return json({ error: 'this offer is no longer valid (the grant was revoked or expired)' }, 409);
    const custodian = String(body.custodian ?? '').toLowerCase();
    if (custodian && (!ADDRESS.test(custodian) || !(await isCustodian(env, person, custodian)))) {
      return json({ error: 'that custodian does not control your account' }, 400);
    }
    const linkKey = `related:${person}:${org}`;
    const existing = (await readJson<Record<string, unknown>>(env.AUTH_CODES, linkKey)) ?? {};
    await env.AUTH_CODES.put(linkKey, JSON.stringify({
      ...existing,
      orgAgent: org,
      orgName: existing.orgName ?? offer.orgName,
      purpose: existing.purpose ?? 'co-manager',
      requestedBy: existing.requestedBy ?? 'home-co-manager',
      kind: existing.kind ?? 'org',
      parent: existing.parent ?? offer.offeredBy,
      relationship: 'steward',
      stewardshipDelegation: offer.delegation,
      createdAt: existing.createdAt ?? Date.now(),
    }));
    const idxKey = `related-idx:${person}`;
    const idx = (await readJson<string[]>(env.AUTH_CODES, idxKey)) ?? [];
    if (!idx.includes(org)) await env.AUTH_CODES.put(idxKey, JSON.stringify([...idx, org]));
    const { delegation: _accepted, ...kept } = offer;
    await env.AUTH_CODES.put(offerKey(person, org), JSON.stringify({ ...kept, acceptedAt: Date.now(), ...(custodian ? { custodian } : {}) } satisfies CoManagerOffer), { expirationTtl: OFFER_TTL_S });
    console.info('[co-manager] accepted', { org, person, custodian: custodian || null });
    return json({ ok: true });
  }
  return json({ error: 'unknown action' }, 400);
};
