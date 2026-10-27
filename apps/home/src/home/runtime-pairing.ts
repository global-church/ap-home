// Spec 400 W1b — PAIR A RUNTIME at the Home. The person's own Claude Code / goose / Codex joins a workspace as a
// `.svc` member from one screen: the Home mints a code on her agent, the runtime claims it with a key it generated
// (`ap runtime pair <code>`), and she APPROVES here — her browser charters the member if it does not exist, invites
// it into the workspace she stewards, and equips it (session wire, steward link, vault key, playbook, host, messaging
// rail, open mandate) with EVERY signature hers, the connected custodian's. The record goes back through the code;
// the runtime takes it once. Nothing here is authority the runtime brings: every grant is hers and revocable on the
// grants screen.
import type { Address, Hex } from '@agenticprimitives/types';
import { equipRuntimeMember, type Contracts, type CustodianSigner, type PairingStateV1, type PairingOptionsV1, type RuntimeHostV1 } from '@agenticprimitives/runtime-member/equip';
import { CONTRACTS, CHAIN_ID } from '../lib/chain';
import { A2A_DOMAIN, DEMO_EDGE_ORIGIN_DEFAULT, SKILLS_REGISTRY_ORIGIN, nameLabel } from '../lib/domain';
import { signHashFor, resolveVia, type Via } from './onboarding';
import { createAgentWithBirthrights } from '../components/portal/ManagedAgents';
import { issueOrganizationResourceAccessDelegation, toWire } from '../lib/delegation';
import { MCP_SERVER_ID } from '../lib/inbox-delivery';
import { recordInvitation } from './ask-record';

export type { PairingStateV1, PairingOptionsV1 };

const j = async (r: Response): Promise<Record<string, unknown>> => { const t = await r.text(); try { return JSON.parse(t) as Record<string, unknown>; } catch { return { _raw: t.slice(0, 200), _status: r.status }; } };

async function op(me: Address, name: string, session: string, body: Record<string, unknown>): Promise<Record<string, unknown>> {
  return j(await fetch(`/a2a/interactions/${me.toLowerCase()}/runtime.pairing.${name}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ session, ...body }) }));
}

export async function mintPairing(me: Address, session: string, handle: string, options: PairingOptionsV1): Promise<PairingStateV1> {
  const r = await op(me, 'mint', session, { handle: nameLabel(handle), options });
  if (r.ok !== true || !r.pairing) throw new Error(String(r.error ?? 'the code was not minted'));
  return r.pairing as PairingStateV1;
}
export async function listPairings(me: Address, session: string): Promise<PairingStateV1[]> {
  const r = await op(me, 'list', session, {});
  if (r.ok !== true) throw new Error(String(r.error ?? 'pairings could not be read'));
  return (r.pairings as PairingStateV1[]) ?? [];
}
export async function cancelPairing(me: Address, session: string, code: string): Promise<void> {
  const r = await op(me, 'cancel', session, { code });
  if (r.ok !== true) throw new Error(String(r.error ?? 'the code was not cancelled'));
}

/** The command the person pastes where the runtime runs. */
export const pairCommand = (code: string): string => `npx @agenticprimitives/runtime-member pair ${code} --home ${typeof window !== 'undefined' ? window.location.origin : 'https://<your home>'}`;

export interface ApproveInput {
  me: Address;
  handle: string;              // the person's typed name (alice.me)
  session: string;
  credential: string | undefined; // profile.credential → via
  sessionVia: string | undefined;
  pairing: Extract<PairingStateV1, { state: 'claimed' }>;
  /** The workspaces this person stewards (address → stewardship wire), for the invitation. */
  stewarded: Array<{ agent: Address; name: string; stewardshipDelegation?: unknown }>;
  onStep: (s: string) => void;
}

/** The ceremony behind Approve. Idempotent where the world already agrees (an existing member, an existing link). */
export async function approvePairing(i: ApproveInput): Promise<{ ok: true; recordName: string } | { ok: false; error: string }> {
  const via: Via = resolveVia(i.credential, i.sessionVia);
  const auth = { token: i.session };
  const o = i.pairing.options;
  try {
    // 1. the member exists — chartered by her, custodied by her credential
    i.onStep(`Checking ${o.member}…`);
    let info = await j(await fetch(`/connect/name-info?name=${encodeURIComponent(o.member)}`)) as { exists?: boolean; agent?: string; deployed?: boolean };
    if (!(info.exists && info.agent && info.deployed !== false)) {
      i.onStep(`Chartering ${o.member}…`);
      const made = await createAgentWithBirthrights({ kind: 'service', label: nameLabel(o.member), parent: i.me, person: i.me, via }, i.session, i.onStep);
      if (!made.ok) return { ok: false, error: `could not charter ${o.member}: ${made.error}` };
      for (let n = 0; n < 15; n++) {
        info = await j(await fetch(`/connect/name-info?name=${encodeURIComponent(o.member)}`)) as typeof info;
        if (info.exists && info.agent && info.deployed !== false) break;
        await new Promise((r) => setTimeout(r, 2000));
      }
      if (!(info.exists && info.agent)) return { ok: false, error: `${o.member} was chartered but does not resolve yet — approve again in a moment` };
    }
    const member = String(info.agent).toLowerCase() as Address;

    // 2. the workspace's invitation — her act as its steward (kept when the roster already lists the member)
    const ws = await j(await fetch(`/connect/name-info?name=${encodeURIComponent(o.workspace)}`)) as { exists?: boolean; agent?: string };
    if (!(ws.exists && ws.agent)) return { ok: false, error: `${o.workspace} does not resolve here` };
    const workspace = String(ws.agent).toLowerCase() as Address;
    const stewarded = i.stewarded.find((s) => s.agent.toLowerCase() === workspace);
    if (stewarded) {
      i.onStep(`Inviting ${o.member} into ${o.workspace}…`);
      const signOrg = await signHashFor(via, workspace, auth);
      const grant = toWire(await issueOrganizationResourceAccessDelegation(workspace, member, MCP_SERVER_ID, signOrg));
      const rec = await recordInvitation({ org: workspace, invitee: member, memberAccessDelegation: grant, invited: true }, i.session);
      if (!rec.ok) return { ok: false, error: `the invitation was not recorded: ${rec.error}` };
    } else {
      i.onStep(`${o.workspace} is not one you steward — its steward must invite ${o.member}`);
    }

    // 3. equip — every signature the custodian's, in this browser
    const signPerson = await signHashFor(via, i.me, auth);
    const custodian: CustodianSigner = { bearer: i.session, agent: i.me, signDigest: (d: Hex) => signPerson(d) };
    const c = CONTRACTS as Record<string, Address>;
    const contracts: Contracts = { chainId: CHAIN_ID, delegationManager: c.delegationManager!, timestampEnforcer: c.timestampEnforcer!, allowedMethodsEnforcer: c.allowedMethodsEnforcer!, valueEnforcer: c.valueEnforcer!, allowedTargetsEnforcer: c.allowedTargetsEnforcer!, agentRelationship: c.agentRelationship!, agentNameRegistry: c.agentNameRegistry!, permissionlessSubregistry: c.permissionlessSubregistry!, ...(c.digestBindingEnforcer ? { digestBindingEnforcer: c.digestBindingEnforcer } : {}) };
    const wake: RuntimeHostV1 | undefined = i.pairing.claim.wake && typeof i.pairing.claim.wake === 'object' ? (i.pairing.claim.wake as RuntimeHostV1)
      : o.wake === 'container' ? { v: 1, kind: 'container' } : typeof o.wake === 'object' ? { v: 1, kind: 'url', url: o.wake.url } : undefined;
    if (!SKILLS_REGISTRY_ORIGIN) throw new Error('pairing a runtime needs a skills registry, and this Home has none');
    i.onStep(`Equipping ${o.member} for its key…`);
    const record = await equipRuntimeMember({
      home: window.location.origin, edge: DEMO_EDGE_ORIGIN_DEFAULT, a2a: `https://${A2A_DOMAIN}`, call: { home: window.location.origin, a2a: `${window.location.origin}/a2a` },
      member: o.member, workspace: o.workspace, contracts, custodian, address: i.pairing.claim.address as Address,
      registry: { origin: SKILLS_REGISTRY_ORIGIN, context: 'agentic-trust', archetype: 'runtime-member' },
      validForSeconds: o.validForSeconds,
      ...(wake ? { wake } : {}),
      ...(o.messagingTo.length ? { messagingTo: o.messagingTo as Address[] } : {}),
      ...(o.openMandate.length ? { openMandate: o.openMandate, ...(o.messagingTo.length ? { openMandateLocations: o.messagingTo as Address[] } : {}) } : {}),
      log: (l) => i.onStep(l.length > 90 ? `${l.slice(0, 87)}…` : l),
    });

    // 4. hand it back through the code
    i.onStep('Handing the record to the runtime…');
    const done = await op(i.me, 'complete', i.session, { code: i.pairing.code, record });
    if (done.ok !== true) return { ok: false, error: String(done.error ?? 'the record was not handed over') };
    return { ok: true, recordName: record.name };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) };
  }
}
