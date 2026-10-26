'use client';
// spec 275 — the member's Smart-Agent tree, split across the portal's dedicated areas:
//   /organizations→ OrganizationsManager   (orgs + each org's treasury)
//   /treasuries   → TreasuriesRollup        (every treasury, personal + org)
// Each agent is an on-chain SA with an EXACT name, custodied by the member's ROOT credential,
// created in one gasless prompt. Links are PRIVATE vault credentials (ADR-0025), read back from
// the same /connect/related-orgs vault (MAM-D7) via listManagedAgents.
import { CoManagerOffers } from './CoManagers';
import { useEffect, useState } from 'react';
import { ExplorerLink } from '../shared/ExplorerLink';
import { FleetLines } from './FleetLines';
import { fundThroughHarness } from '../../home/fund-harness';
import { createPublicClient, http, formatUnits } from 'viem';
import { baseSepolia } from 'viem/chains';
import { AGENT_NAME_PARENT } from '../../lib/domain';
import { typedTldForKind, createManagedAgent, nameManagedAgent, personSignHash, listManagedAgents, invalidateRelatedOrgs, signsWithoutPrompt, type AgentKind, type ManagedAgent, type CreateManagedAgentResult } from '../../connect-client';
import { BusyButton } from '../shared/BusyButton';
import { PrimaryPayee } from './PrimaryPayee';
import { assignDefaultArchetype } from '../../home/default-archetype';
import { emitControlEvent } from '../../home/control-plane';
import { activateVaultIfNeeded, activateInboxDeliveryIfNeeded, activateInteractionsIfNeeded, governWorkspace, signHashFor, type Via } from '../../home/onboarding';
import { setOrgLifecycleStatus } from '../../home/org-lifecycle';
import { orgStatusOf, STATUS_LABEL, type OrgSurface } from '../../lib/org-lifecycle';
import type { DelegationWire } from '../../lib/delegation';
import { ORG_INTERACTIONS_SESSION_LEAF_TTL_SECONDS } from '../../lib/delegation';
import { vaultWriteWithDelegation } from '../../lib/vault-client';
import { COINS, FUNDING_COIN, shown, type Coin } from '../../lib/coins';
import { CONTRACTS } from '../../lib/chain';
import { AddressChip } from '../shared/AddressChip';
import { BuildingIcon, LandmarkIcon, UserIcon } from '../shared/Icons';
import { useRegisteredName } from '../../lib/reverse-name';
import { ConnectTreasuryModal } from './ConnectTreasuryModal';
import { ConnectedHosts } from './ConnectedHosts';
import { agentClassOf, orgKindWordOf, creatableKinds, type CreatableKind } from '../../lib/agent-class';
import { BasisLine } from './BasisLine';

import { Loading } from '../shared/Loading';
import { SkeletonRows } from '../../ui';
const ERC20_BALANCE_ABI = [
  { type: 'function', name: 'balanceOf', stateMutability: 'view', inputs: [{ name: 'a', type: 'address' }], outputs: [{ type: 'uint256' }] },
] as const;

const lc = (s: string) => s.toLowerCase();

const KIND_LABEL: Record<AgentKind, string> = {
  person: 'Another person of yours',
  'person-treasury': 'Personal treasury',
  org: 'Organization',
  team: 'Team',
  circle: 'Circle',
  church: 'Church',
  household: 'Household',
  'org-treasury': 'Org treasury',
  service: 'Service agent',
  workspace: 'App workspace',
};

/** Cross-component refresh signal: EVERY `useManagedAgents` instance (topbar switcher, org lists,
 *  workspace pages) reloads when this fires — dispatch after any mutation that changes an agent's
 *  identity surface (naming, creating), so dropdowns update without a page refresh. */
export const AGENTS_CHANGED_EVENT = 'ap:agents-changed';
export const notifyAgentsChanged = (): void => {
  // Any writer that announces a change also drops the shared `/connect/related-orgs` payload, so a
  // caller outside connect-client (org lifecycle, enrolment, discussions) can't be served a stale list.
  invalidateRelatedOrgs();
  window.dispatchEvent(new Event(AGENTS_CHANGED_EVENT));
};

/** Shared loader for the member's managed agents — one read path (MAM-D7).
 *
 *  spec 342 — `surface` decides which lifecycle states come back, and the DEFAULT IS THE NARROW
 *  ONE: a screen that never heard of the spec shows only active organizations (and drops the
 *  treasuries hanging off hidden ones). Pass 'roster' for the organizations list, which must show
 *  inactive orgs so they can be reactivated, and 'any' for a page addressed by a specific SA. */
export function useManagedAgents(token: string | null, surface: OrgSurface = 'working') {
  const [agents, setAgents] = useState<ManagedAgent[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [reloadKey, setReloadKey] = useState(0);
  useEffect(() => {
    const bump = (): void => { invalidateRelatedOrgs(); setReloadKey((k) => k + 1); };
    window.addEventListener(AGENTS_CHANGED_EVENT, bump);
    return () => window.removeEventListener(AGENTS_CHANGED_EVENT, bump);
  }, []);
  useEffect(() => {
    if (!token) { setLoaded(true); return; }
    let cancelled = false;
    void listManagedAgents(token, surface)
      .then((a) => { if (!cancelled) { setAgents(a); setLoaded(true); } })
      .catch(() => { if (!cancelled) setLoaded(true); });
    return () => { cancelled = true; };
  }, [token, reloadKey, surface]);
  // `version` bumps on every reload — treasury balances re-read when it changes (e.g. after funding).
  return { agents, loaded, version: reloadKey, reload: () => setReloadKey((k) => k + 1) };
}

/** Live balance read for a treasury SA, for EVERY coin this Home knows about (`lib/coins.ts`).
 *
 *  It read exactly one — the demo USDC — and printed the answer as "Balance: N USDC", which is not
 *  the balance of the account but the balance of one asset in it. A treasury holding ten thousand
 *  Sheqels of a relying app's currency read "0.00 USDC" here, and its owner reasonably concluded the
 *  money was gone. All the coins are read at once; one that fails costs its own row and no other.
 *
 *  `refreshKey` forces a re-read (the address is stable, so funding wouldn't otherwise refresh it). */
function useCoinBalances(address?: string, refreshKey?: number): { coin: Coin; amount: bigint | null }[] {
  const [bals, setBals] = useState<{ coin: Coin; amount: bigint | null }[]>(() => COINS.map((coin) => ({ coin, amount: null })));
  useEffect(() => {
    if (!address) return;
    let cancelled = false;
    const pub = createPublicClient({ chain: baseSepolia, transport: http('/a2a/rpc') });
    void Promise.all(
      COINS.map(async (coin) => {
        try {
          const b = await pub.readContract({ address: coin.address, abi: ERC20_BALANCE_ABI, functionName: 'balanceOf', args: [address as `0x${string}`] });
          return { coin, amount: b as bigint };
        } catch {
          return { coin, amount: null };
        }
      }),
    ).then((got) => { if (!cancelled) setBals(got); });
    return () => { cancelled = true; };
  }, [address, refreshKey]);
  return bals;
}

export function BalanceLine({ address, refreshKey }: { address: string; refreshKey?: number }) {
  const bals = useCoinBalances(address, refreshKey);
  const rows = shown(bals);
  return (
    <span style={{ fontSize: '.82rem', color: 'var(--c-g500, #64748b)' }}>
      Balance:{' '}
      {rows.map((b, i) => (
        <span key={b.coin.address}>
          {i > 0 ? ' · ' : ''}
          <b>{b.amount !== null ? `${Number(formatUnits(b.amount, b.coin.decimals)).toFixed(2)} ${b.coin.symbol}` : '—'}</b>
        </span>
      ))}
    </span>
  );
}

/** Fund a treasury with demo USDC (gasless mint via the home SA). On success, bumps the parent
 *  reload so the balance re-reads. */
export function FundForm({
  treasury, person, via, token, onDone,
}: {
  treasury: string; person: string; via: string; token: string; onDone: () => void;
}) {
  const [open, setOpen] = useState(false);
  const [amt, setAmt] = useState('10');
  // Which coin to mint. Every coin this Home knows on its chain is a TEST coin with an open mint (the demo
  // USDC, the card room's SHQ), so funding in any of them is the same faucet call with a different asset —
  // a treasury has no currency of its own; it holds whatever was put in it.
  const [coin, setCoin] = useState<Coin>(FUNDING_COIN);
  const [busy, setBusy] = useState(false);
  const [step, setStep] = useState('');
  const [err, setErr] = useState('');
  // Whether THIS session signs without a device prompt. `null` until known — the note says nothing rather
  // than guessing, because guessing is how it came to promise "no wallet prompt" to a wallet home.
  const [promptless, setPromptless] = useState<boolean | null>(null);
  useEffect(() => {
    let live = true;
    void signsWithoutPrompt(via, token).then((v) => { if (live) setPromptless(v); }).catch(() => { if (live) setPromptless(null); });
    return () => { live = false; };
  }, [via, token]);

  async function go() {
    const n = Number(amt);
    if (!(n > 0)) { setErr('Enter an amount greater than 0.'); return; }
    setBusy(true); setErr(''); setStep('');
    // Through the HARNESS (spec 361 I4): this button and "fund my treasury with N usdc" are one
    // implementation now. Same one signature (the mandate replaces the direct userOp sign), and the
    // converged path fires the spec-360 FundingReceipt the direct mint never left.
    setStep('Granting the funding authority…');
    const sign = await personSignHash(person as `0x${string}`, via, token);
    if (typeof sign !== 'function') { setBusy(false); setErr(sign.error); return; }
    // Whole coins → the atomic figure the rail takes, at the coin's own decimals. Same number the caller
    // used to hand over; the conversion just moved to the one place that knows the decimals.
    const res = await fundThroughHarness({
      treasury: treasury as `0x${string}`,
      amount: BigInt(Math.round(n * 10 ** coin.decimals)),
      ...(coin.primary ? {} : { asset: coin.address }),
      display: `${n} ${coin.symbol.toLowerCase()}`,
      session: { token },
      signHash: sign,
    });
    setBusy(false);
    if (!res.ok) { setErr(res.error); return; }
    setOpen(false);
    onDone();
  }

  if (!open) {
    return (
      <button type="button" className="btn-ghost" style={{ marginTop: '.5rem', fontSize: '.78rem', padding: '.25rem .55rem' }} onClick={() => setOpen(true)}>
        {COINS.length > 1 ? 'Fund' : `Fund with ${FUNDING_COIN.symbol}`}
      </button>
    );
  }
  return (
    <div style={{ marginTop: '.5rem', display: 'flex', flexDirection: 'column', gap: '.4rem' }}>
      <BasisLine needs="test coins minted straight into this treasury — no account is debited (assets live only in treasuries); your credential signs the funding mandate" />
      <div style={{ display: 'flex', gap: '.4rem', alignItems: 'center' }}>
        <input type="number" min="0" step="1" value={amt} onChange={(e) => setAmt(e.target.value)} disabled={busy}
          style={{ width: 90, padding: '.4rem .55rem', fontSize: '.85rem', border: '1px solid var(--c-g200, #e2e8f0)', borderRadius: 6 }} />
        {COINS.length > 1 ? (
          <select value={coin.address} disabled={busy} onChange={(e) => setCoin(COINS.find((c) => c.address === e.target.value) ?? FUNDING_COIN)}
            style={{ padding: '.4rem .55rem', fontSize: '.85rem', border: '1px solid var(--c-g200, #e2e8f0)', borderRadius: 6 }} aria-label="Coin">
            {COINS.map((c) => <option key={c.address} value={c.address}>{c.symbol}</option>)}
          </select>
        ) : (
          <span style={{ fontSize: '.82rem', color: 'var(--c-g500, #64748b)' }}>{FUNDING_COIN.symbol}</span>
        )}
      </div>
      <div style={{ display: 'flex', gap: '.4rem' }}>
        <BusyButton busy={busy} busyLabel={step || 'Funding…'} className="btn-primary" style={{ fontSize: '.8rem', padding: '.35rem .7rem' }} onClick={() => void go()}>
          Fund
        </BusyButton>
        <button type="button" className="btn-ghost" style={{ fontSize: '.8rem', padding: '.35rem .7rem' }} disabled={busy} onClick={() => { setOpen(false); setErr(''); }}>
          Cancel
        </button>
      </div>
      {/* Say what THIS session will actually do. "no wallet prompt" was written for KMS homes and read as
          a promise by everyone: a wallet home signs the mint with its own credential, and a seeded demo
          person signs at the Home. Gas is sponsored either way; the signature is not always free. */}
      <p className="onboarding-note" style={{ margin: 0 }}>
        Mints test {coin.symbol} to this treasury{coin.primary ? ' — the coin the estate\u2019s apps settle in' : ''}. Gas is sponsored.{' '}
        {promptless === null ? '' : promptless ? 'Your home signs it: no wallet prompt.' : 'Your wallet will ask you to sign it.'}
      </p>
      {err && <p className="onboarding-hint taken" style={{ margin: 0 }}>{err}</p>}
    </div>
  );
}

/**
 * Charter one managed agent AND everything it is born with — the create ceremony itself, the
 * storage an organization needs before its first member arrives, the playbook the effect resolver
 * reads off the payer, and the member's own timeline entry — in one call that RETURNS THE AGENT.
 *
 * This was the body of `CreateAgentForm.create`, and it is a function now because the form is no
 * longer the only surface that charters an agent. The treasury ceremony (`app/choose-treasury`)
 * creates a person treasury on behalf of an app that asked for one, and it has to hand that
 * treasury's ADDRESS straight back to the app — which a form whose only output is `onDone()`
 * cannot do. Copying the sequence over there would have left four best-effort steps free to drift
 * apart: a treasury born without the playbook that makes it say what it paid, a hole in the
 * timeline, an org with no channel storage. One implementation, two callers, and the result comes
 * back.
 *
 * Everything after the create itself is BEST-EFFORT on purpose. None of it grants anything, and a
 * person's new agent must not fail to exist because a courtesy failed.
 */
export async function createAgentWithBirthrights(
  input: { kind: AgentKind; label?: string; parent: string; person: string; via: string },
  token: string,
  onStep: (s: string) => void,
): Promise<{ ok: true; result: CreateManagedAgentResult } | { ok: false; error: string }> {
  const { kind, label, parent, person, via } = input;
  // A WORKSPACE CHARTERED INSIDE AN ORGANIZATION (2026-10-26): stewarded by the PERSON (an organization has no session,
  // and every steward gate checks the wire against the person), then given storage and its governor — exactly what the
  // onboarding ceremony does (governWorkspace). Before this, the button made a workspace stewarded by the org itself,
  // with no storage and no governance records, which no steward check (the operator directory's included) accepts.
  const governedWs = kind === 'workspace' && parent.toLowerCase() !== person.toLowerCase();
  let governorRow: ManagedAgent | undefined;
  if (governedWs) {
    governorRow = (await listManagedAgents(token, 'any').catch(() => [] as ManagedAgent[])).find((a) => a.agent.toLowerCase() === parent.toLowerCase());
    if (!governorRow?.stewardshipDelegation) return { ok: false, error: 'You need to manage this organization to charter a workspace inside it.' };
  }
  const res = await createManagedAgent(
    { kind, label, parent: parent as `0x${string}`, person: person as `0x${string}`, via, ...(governedWs ? { steward: person as `0x${string}` } : {}) },
    token, onStep,
  );
  if (!res.ok) return res;
  if (governedWs) {
    const wsStewardship = res.result.stewardshipDelegation as DelegationWire | undefined;
    if (!wsStewardship) return { ok: false, error: `${res.result.name || 'The workspace'} was created without a stewardship grant, so its governor could not be recorded.` };
    const governed = await governWorkspace({
      ws: res.result.agent, wsStewardship, governor: parent.toLowerCase() as `0x${string}`,
      orgStewardship: governorRow!.stewardshipDelegation as DelegationWire,
      label: res.result.name || label || '', governorName: governorRow!.name || '', purpose: 'workspace',
      person: person as `0x${string}`, via: via.toLowerCase() as Via, auth: { token }, token,
      onStep: (_n, line) => onStep(line),
    });
    if (!governed.ok) return { ok: false, error: governed.error };
    invalidateRelatedOrgs();
  }
  // spec 321 — enable channel storage AT CREATE so the steward never meets the "Enable (steward)"
  // banner: bind the org's vault key + issue its standing delivery grant (channels.data + message
  // bodies + invite tracking) signed AS THE ORG. Zero prompts on the KMS family (C_sub custodies
  // the org); device prompts on passkey/wallet. Best-effort — the steward-gated Enable button on
  // the channels page remains the recovery path if either leg fails.
  if (kind === 'org') {
    try {
      const v = via.toLowerCase() as Via;
      onStep('Enabling channel storage…');
      const bound = await activateVaultIfNeeded(res.result.agent, v, { token });
      if (!bound.ok) throw new Error(bound.error);
      const grant = await activateInboxDeliveryIfNeeded(res.result.agent, v, { token });
      if (!grant.ok) throw new Error(grant.error);
      // spec 322 W2.2 — plane-B interactions grant, same ceremony (inert until provisioned).
      const ix = await activateInteractionsIfNeeded(res.result.agent, v, { token }, false, ORG_INTERACTIONS_SESSION_LEAF_TTL_SECONDS);
      if (!ix.ok) console.warn('[org-create] interactions grant not provisioned:', ix.error);
      // spec 321 items 1+3 — seed what members will look at first: the org's profile record (the
      // "About this organization" card + roster read) and a default #general channel, so a fresh
      // org is USABLE without any steward follow-up. Best-effort, like the storage enable above.
      onStep('Setting up the organization…');
      if (res.result.stewardshipDelegation) {
        await vaultWriteWithDelegation(res.result.stewardshipDelegation, 'org.profile', { v: 1, displayName: res.result.name || label || '' }).catch((e) => console.warn('[org-create] org profile seed failed:', e));
      }
      await fetch('/connect/channels', {
        method: 'POST',
        headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
        body: JSON.stringify({ action: 'create', communityId: res.result.agent.toLowerCase(), title: 'general' }),
      }).catch((e) => console.warn('[org-create] default channel failed:', e));
    } catch (e) {
      console.warn('[org-create] channel storage not auto-enabled (use Enable on the channels page):', e);
    }
  }
  // SPEC 428 W3 — A TEAM GRANTS ITS ORGANIZATION A CONTENT READ OF ITSELF, at charter. The team's records stay the team's
  // (its vault); the organization's stewards read them through this `team → org` grant (content, discussion,
  // coordination only — never custody, membership or members' private records). Signed AS THE TEAM by the person who
  // just chartered it (its custodian), projected into `org-teams:<org>` for the org's stewards. Best-effort: a team is
  // never refused for want of it, and `scripts/backfill-428-team-read.mts` is the recovery path.
  if (kind === 'team' && parent.toLowerCase() !== person.toLowerCase()) {
    try {
      const { issueOrgReadDelegation, toWire } = await import('../../lib/delegation');
      const { MCP_SERVER_ID } = await import('../../lib/inbox-delivery');
      const { GOVERNED_CONTENT_SCOPE } = await import('../../lib/workspace-governor');
      const signTeam = await signHashFor(via.toLowerCase() as Via, res.result.agent, { token });
      const grant = toWire(await issueOrgReadDelegation(res.result.agent, parent as `0x${string}`, { server: MCP_SERVER_ID, resources: GOVERNED_CONTENT_SCOPE }, signTeam));
      await fetch('/connect/related-orgs', {
        method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
        body: JSON.stringify({ person, orgAgent: parent.toLowerCase(), governedTeam: { team: res.result.agent.toLowerCase(), teamName: res.result.name || label || '', grant } }),
      });
    } catch (e) { console.warn('[team-create] the organization content-read grant was not minted:', e instanceof Error ? e.message : String(e)); }
  }
  // THE PLAYBOOK IT IS BORN WITH (spec 354 §3). A treasury with no assignment runs the bare harness —
  // which is a documented state, except that the spec-360 effect resolver reads the PAYER's playbook,
  // so an unassigned treasury moves money and tells nobody.
  const born = await assignDefaultArchetype(res.result.agent, kind, token);
  if (!born.ok) console.warn(`[agent-create] no default playbook for ${kind}:`, born.reason);
  // Control-plane timeline (spec 310 W4): a new agent joined the member's tree.
  void emitControlEvent(token, 'agent-added', []);
  notifyAgentsChanged(); // every dropdown/list instance (topbar switcher included) re-reads immediately
  return res;
}

/** Inline "name it and create" form for one agent slot (MAM-D4 exact-name, MAM-D5 one prompt).
 *
 *  `choices` turns the single-slot form into a chartering form: the person picks WHAT to create, and the
 *  suffix beside the name field is the one that kind will actually claim. The list is filtered to the
 *  typed roots this chain has provisioned, so it never offers a kind whose name would fail to claim. */
export function CreateAgentForm({
  kind: fixedKind, choices, parent, person, token, via, onDone, cta, prominent,
}: {
  kind?: AgentKind; choices?: CreatableKind[]; parent: string; person: string; token: string; via: string; onDone: () => void; cta: string;
  /** Render the collapsed trigger as a PRIMARY button (the page's main action), not a quiet ghost link. */
  prominent?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [label, setLabel] = useState('');
  const [busy, setBusy] = useState(false);
  const [step, setStep] = useState('');
  const [err, setErr] = useState('');
  const [picked, setPicked] = useState<AgentKind | null>(null);

  const kind: AgentKind = picked ?? fixedKind ?? choices?.[0]?.kind ?? 'org';
  const choice = choices?.find((c) => c.kind === kind);
  // Counterparty-facing agents MUST be named — an organization, a team, a service others will address.
  // Plumbing (a treasury) may defer. The table says which; a single-kind form keeps the old rule.
  const nameRequired = choice ? choice.nameRequired : kind === 'org';

  async function create(named: boolean) {
    const clean = label.trim().toLowerCase();
    if (named && clean.length < 3) {
      setErr(nameRequired ? 'Organizations require a name — at least 3 characters.' : 'Pick a name with at least 3 characters, or create it unnamed.');
      return;
    }
    setBusy(true); setErr(''); setStep('');
    const res = await createAgentWithBirthrights(
      { kind, label: named ? clean : undefined, parent, person, via }, token, setStep,
    );
    setBusy(false);
    if (!res.ok) { setErr(res.error); return; }
    setOpen(false); setLabel('');
    onDone();
  }

  if (!open) {
    return (
      <button type="button" className={prominent ? 'ui-btn ui-btn--primary' : 'btn-ghost'} style={prominent ? { marginTop: '.5rem' } : { marginTop: '.5rem', fontSize: '.8rem', padding: '.3rem .6rem' }} onClick={() => setOpen(true)}>
        {cta}
      </button>
    );
  }
  return (
    <div style={{ marginTop: '.55rem', display: 'flex', flexDirection: 'column', gap: '.4rem' }}>
      {choices && choices.length > 1 && (
        <label style={{ display: 'flex', gap: '.4rem', alignItems: 'center', fontSize: '.82rem' }}>
          <span style={{ color: 'var(--c-g500, #64748b)' }}>Create</span>
          <select
            value={kind} disabled={busy} onChange={(e) => { setPicked(e.target.value as AgentKind); setErr(''); }}
            data-testid="create-kind"
            style={{ flex: 1, padding: '.35rem .5rem', fontSize: '.85rem', border: '1px solid var(--c-g200, #e2e8f0)', borderRadius: 6 }}
          >
            {choices.map((c) => (
              <option key={c.kind} value={c.kind}>{c.label} · .{typedTldForKind(c.kind)?.tld ?? AGENT_NAME_PARENT}</option>
            ))}
          </select>
        </label>
      )}
      <div style={{ display: 'flex', gap: '.4rem', alignItems: 'center' }}>
        <input value={label} onChange={(e) => setLabel(e.target.value)} placeholder={nameRequired ? 'name (required)' : 'name (optional)'} disabled={busy}
          style={{ flex: 1, padding: '.4rem .55rem', fontSize: '.85rem', border: '1px solid var(--c-g200, #e2e8f0)', borderRadius: 6 }} />
        {/* The suffix this agent will ACTUALLY be named under. It was hardcoded `.impact` — the legacy
            root — while the claim already used the typed one for the kind (`typedTldForKind`), so the
            form promised `.impact` and produced `.org`. Worse than cosmetic: the suffix names the derived
            TYPE (spec 346), and `.impact` carries none, so the label said "this will not be listable"
            about an agent that would be. */}
        <span style={{ fontSize: '.82rem', color: 'var(--c-g500, #64748b)' }}>.{typedTldForKind(kind)?.tld ?? AGENT_NAME_PARENT}</span>
      </div>
      <div style={{ display: 'flex', gap: '.4rem', flexWrap: 'wrap' }}>
        <BusyButton busy={busy} busyLabel={step || 'Working…'} className="btn-primary" style={{ fontSize: '.8rem', padding: '.35rem .7rem' }} onClick={() => void create(true)}>
          Create + name
        </BusyButton>
        {!nameRequired && (
          <button type="button" className="btn-ghost" style={{ fontSize: '.8rem', padding: '.35rem .7rem' }} disabled={busy} onClick={() => void create(false)}>
            Create without a name
          </button>
        )}
        <button type="button" className="btn-ghost" style={{ fontSize: '.8rem', padding: '.35rem .7rem' }} disabled={busy} onClick={() => { setOpen(false); setErr(''); }}>
          Cancel
        </button>
      </div>
      <p className="onboarding-note" style={{ margin: 0 }}>
        Deploys its own Smart Agent, stewarded by you (your key signs for it) — one {via === 'wallet' ? 'wallet' : 'device'} prompt, gas sponsored.
        {' '}{choice?.blurb ? `${choice.blurb} ` : ''}{nameRequired ? 'It is counterparty-facing, so a name is required.' : 'A name is optional; you can name it later.'}
      </p>
      {err && <p className="onboarding-hint taken" style={{ margin: 0 }}>{err}</p>}
    </div>
  );
}

/** Claim a name for an already-deployed, NAMELESS managed agent (name-later, one gasless prompt). */
export function NameAgentForm({
  agent, kind, parent, person, token, via, onDone,
}: {
  agent: string; kind: AgentKind; parent: string; person: string; token: string; via: string; onDone: () => void;
}) {
  const [open, setOpen] = useState(false);
  const [label, setLabel] = useState('');
  const [busy, setBusy] = useState(false);
  const [step, setStep] = useState('');
  const [err, setErr] = useState('');

  async function go() {
    const clean = label.trim().toLowerCase();
    if (clean.length < 3) { setErr('Pick a name with at least 3 characters.'); return; }
    setBusy(true); setErr(''); setStep('');
    const res = await nameManagedAgent(
      { agent: agent as `0x${string}`, label: clean, kind, parent: parent as `0x${string}`, person: person as `0x${string}`, via },
      token, setStep,
    );
    setBusy(false);
    if (!res.ok) { setErr(res.error); return; }
    setOpen(false); setLabel('');
    notifyAgentsChanged(); // every dropdown/list instance (topbar switcher included) re-reads immediately
    onDone();
  }

  if (!open) {
    return (
      <button type="button" className="btn-ghost" style={{ marginTop: '.5rem', fontSize: '.78rem', padding: '.25rem .55rem' }} onClick={() => setOpen(true)}>
        Name it
      </button>
    );
  }
  return (
    <div style={{ marginTop: '.5rem', display: 'flex', flexDirection: 'column', gap: '.4rem' }}>
      <div style={{ display: 'flex', gap: '.4rem', alignItems: 'center' }}>
        <input value={label} onChange={(e) => setLabel(e.target.value)} placeholder="name" disabled={busy}
          style={{ flex: 1, padding: '.4rem .55rem', fontSize: '.85rem', border: '1px solid var(--c-g200, #e2e8f0)', borderRadius: 6 }} />
        {/* The suffix this agent will ACTUALLY be named under. It was hardcoded `.impact` — the legacy
            root — while the claim already used the typed one for the kind (`typedTldForKind`), so the
            form promised `.impact` and produced `.org`. Worse than cosmetic: the suffix names the derived
            TYPE (spec 346), and `.impact` carries none, so the label said "this will not be listable"
            about an agent that would be. */}
        <span style={{ fontSize: '.82rem', color: 'var(--c-g500, #64748b)' }}>.{typedTldForKind(kind)?.tld ?? AGENT_NAME_PARENT}</span>
      </div>
      <div style={{ display: 'flex', gap: '.4rem' }}>
        <BusyButton busy={busy} busyLabel={step || 'Naming…'} className="btn-primary" style={{ fontSize: '.8rem', padding: '.35rem .7rem' }} onClick={() => void go()}>
          Name it
        </BusyButton>
        <button type="button" className="btn-ghost" style={{ fontSize: '.8rem', padding: '.35rem .7rem' }} disabled={busy} onClick={() => { setOpen(false); setErr(''); }}>
          Cancel
        </button>
      </div>
      {err && <p className="onboarding-hint taken" style={{ margin: 0 }}>{err}</p>}
    </div>
  );
}

/** A treasury card — name (or "unnamed" + name-it slot), address, live balance, explorer, fund action, and
 *  (for NAMED treasuries) a "Connect to hosts" popup that runs the bind → authorize → publish ceremony with
 *  the treasury already selected (spec 283/284). */
export function TreasuryCard({
  name, address, sublabel, nameSlot, person, via, token, refreshKey, onFunded,
}: {
  name: string; address: string; sublabel?: string; nameSlot?: React.ReactNode;
  person?: string | null; via?: string; token?: string | null; refreshKey?: number; onFunded?: () => void;
}) {
  const [connectOpen, setConnectOpen] = useState(false);
  return (
    <div className="manage-card">
      <div className="manage-card-head">
        <span className="manage-card-icon"><LandmarkIcon size={17} /></span>
        <span className="manage-card-label">{name || 'Unnamed treasury'}</span>
        <span className="manage-card-badge live">{sublabel ?? KIND_LABEL['person-treasury']}</span>
      </div>
      <div style={{ margin: '.45rem 0' }}><AddressChip address={address as `0x${string}`} size="sm" /></div>
      <p className="manage-card-blurb" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '.5rem' }}>
        <BalanceLine address={address} refreshKey={refreshKey} />
        <ExplorerLink address={address} label="explorer ↗" />
      </p>
      {!name && nameSlot}
      <div style={{ display: 'flex', gap: '.4rem', flexWrap: 'wrap' }}>
        {token && person && onFunded && <FundForm treasury={address} person={person} via={via ?? ''} token={token} onDone={onFunded} />}
        {name && token && (
          <button type="button" className="btn-ghost" style={{ marginTop: '.5rem', fontSize: '.78rem', padding: '.25rem .55rem' }} onClick={() => setConnectOpen(true)}>
            Connect to hosts
          </button>
        )}
      </div>
      {/* The relationship picture — shows only once the treasury has bound its A2A + MCP hosts on-chain. */}
      {name && <ConnectedHosts name={name} address={address} />}
      {connectOpen && token && (
        <ConnectTreasuryModal treasury={address} name={name} person={person} via={via} token={token}
          onClose={() => setConnectOpen(false)} onDone={onFunded} />
      )}
    </div>
  );
}

// ── /you — your personal treasury ───────────────────────────────────────
/** spec 342 — the one place an inactive org is shown, so it is the one place it can be brought
 *  back. Writes the org's own `org.lifecycle` record over the stewardship delegation the tree row
 *  already carries; without that delegation there is nothing to present, so the row says so
 *  instead of offering a button that would 403. */
function ActivateOrgRow({ org, person, token, onDone }: {
  org: ManagedAgent; person: string; token: string; onDone: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const stewardship = org.stewardshipDelegation as DelegationWire | undefined;

  return (
    <div style={{ marginTop: '.5rem', padding: '.55rem .65rem', borderRadius: 8, background: 'var(--color-amber-50, #fffbeb)' }}>
      <p className="manage-card-blurb" style={{ margin: '0 0 .45rem', fontSize: '.78rem' }}>
        Deactivated — hidden everywhere else in your home.
      </p>
      {stewardship ? (
        <BusyButton
          busy={busy}
          busyLabel="Activating…"
          className="btn-ghost"
          style={{ fontSize: '.78rem', padding: '.25rem .55rem' }}
          onClick={() => {
            setBusy(true);
            setErr(null);
            void setOrgLifecycleStatus({
              person: person as `0x${string}`,
              org: org.agent,
              token,
              stewardship,
              status: 'active',
            }).then((r) => {
              setBusy(false);
              if (!r.ok) { setErr(r.error); return; }
              notifyAgentsChanged();
              onDone();
            });
          }}
        >
          Activate
        </BusyButton>
      ) : (
        <p className="manage-card-blurb" style={{ margin: 0, fontSize: '.75rem' }}>
          You hold no stewardship delegation on this organization, so only a steward can activate it.
        </p>
      )}
      {err && <p className="manage-card-blurb" style={{ margin: '.35rem 0 0', fontSize: '.75rem', color: 'var(--c-danger, #dc2626)' }}>{err}</p>}
    </div>
  );
}

// ── /organizations — orgs + each org's treasury + create ────────────────
export function OrganizationsManager({
  token, person, via, onSelect, initialFilter = 'all',
}: { token: string | null; person: string | null; via: string; onSelect?: (orgAgent: string) => void; initialFilter?: 'all' | 'org' | 'service' | 'person' }) {
  // 'roster' (spec 342): this list shows deactivated orgs — it is the route back to activating them.
  const { agents, loaded, version, reload } = useManagedAgents(token, 'roster');
  const [filter, setFilter] = useState<'all' | 'org' | 'service' | 'person'>(initialFilter);
  if (!token || !person) return null;
  // ADR-0046 — the CLASS is the trichotomy (a team is an organization, a treasury is a service); the row
  // says which SUBCLASS it is. The filter groups by class because that is the distinction the substrate
  // makes; it never invents a third category to hold the things that did not fit.
  const orgs = agents.filter((a) => agentClassOf(a.kind) === 'org');
  // A treasury is shown INSIDE the organization it belongs to, so it would read twice here.
  const services = agents.filter((a) => agentClassOf(a.kind) === 'service' && a.kind !== 'org-treasury');
  // OTHER PEOPLE OF YOURS — person-class agents this custodian holds besides the one they are signed in as
  // (a trail name, a pen name, a character in a game). They fell through both filters above and so appeared
  // on no page at all: chartered, custodied, named on chain, and invisible to the person who owns them.
  const others = agents.filter((a) => agentClassOf(a.kind) === 'person');
  const treasuryFor = (org: string) => agents.find((a) => a.kind === 'org-treasury' && lc(a.parent) === lc(org));
  const claimable = (k: AgentKind) => !!typedTldForKind(k);
  // The connected person's own name, for the row that is them. A home with no name yet still has a person.
  const selfRegistered = useRegisteredName((person ?? null) as `0x${string}` | null);
  const selfName = selfRegistered.name ?? '';
  const showPeople = filter === 'all' || filter === 'person';
  const showOrgs = filter === 'all' || filter === 'org';
  const showServices = filter === 'all' || filter === 'service';
  // The filter NARROWS a page that already shows its own structure — it is not the structure. With
  // everything shown, the two classes read as headed sections; picking one hides the other rather than
  // rearranging the page under you.
  const Filter = () => (
    <div className="ui-toolbar">
      <div className="ui-tabs" role="tablist" aria-label="Filter what you steward">
        {([['all', 'All', 1 + others.length + orgs.length + services.length], ['person', 'People', 1 + others.length], ['org', 'Organizations', orgs.length], ['service', 'Services', services.length]] as const).map(([v, l, n]) => (
          <button key={v} type="button" role="tab" aria-selected={filter === v} onClick={() => setFilter(v)} data-testid={`steward-filter-${v}`} className="ui-tab">{l}<span className="ui-count">{n}</span></button>
        ))}
      </div>
    </div>
  );
  const Heading = ({ children, n }: { children: React.ReactNode; n?: number }) => (
    <div className="ui-section-head" style={{ gridColumn: '1 / -1', marginTop: 'var(--sp-3)' }}><h2>{children}{typeof n === 'number' && <span className="ui-count">{n}</span>}</h2></div>
  );

  return (
    <div className="dash-section">
      {/* Offers to co-manage an organization, accepted here as yourself (2026-10-23, CoManagers.tsx). */}
      <CoManagerOffers session={{ token, via, fresh: false }} />
      {/* STRUCTURE FIRST (owner, 2026-10-02): the filter and the prominent "Add an organization" card render
          immediately — neither needs the agent tree — and the rows skeleton while that read is out. */}
      <Filter />
        <div className="manage-grid">
          {/* ADD AN ORGANIZATION — the page's own primary action (owner, 2026-10-02: moved off the header and
              made prominent here, on the Stewardship organizations page). Full-width, amber-accented, at the top
              of the list, with the same gasless in-home charter ceremony. Shown while organizations are in view
              and the `.org` typed root is provisioned on this chain. */}
          {showOrgs && person && claimable('org') && (
            <div className="manage-card" style={{ gridColumn: '1 / -1', borderColor: 'var(--color-amber-500)' }} data-testid="add-organization">
              <div className="manage-card-head">
                <span className="manage-card-icon"><BuildingIcon size={17} /></span>
                <span className="manage-card-label">Add an organization</span>
                <span className="manage-card-badge live">new</span>
              </div>
              <p className="manage-card-blurb">An organization you steward — its own Smart Agent and typed <code>.org</code> name, custodied by you and created gaslessly in your home.</p>
              <CreateAgentForm kind="org" parent={person} person={person} token={token} via={via} onDone={reload} cta="Add an organization" prominent />
            </div>
          )}
          {!loaded ? (
            <div style={{ gridColumn: '1 / -1' }}><SkeletonRows rows={5} lead /></div>
          ) : (
          <>
          {/*
            * YOUR OWN PEOPLE LEAD, AND YOU ARE THE FIRST OF THEM.
            *
            * The first cut listed only the OTHERS, so a custodian who had chartered none saw "People 0" on a
            * page that was showing them their own home — true of the list and false of the person reading
            * it, who plainly has at least one. You are a person of yours; you are simply the DEFAULT one,
            * which is a fact worth stating rather than a row worth hiding. It is also where the choice
            * between them belongs once there is more than one to choose.
            */}
          {showPeople && <Heading n={1 + others.length}>People</Heading>}
          {showPeople && (
            <div className="manage-card" key="self">
              <div className="manage-card-head">
                <span className="manage-card-icon"><UserIcon size={17} /></span>
                <span className="manage-card-label">{selfName || 'You'}</span>
                <span className="manage-card-badge live">default</span>
              </div>
              <p className="manage-card-blurb">
                The person your home opens as. Everything that needs to reach YOU addresses this one.
              </p>
            </div>
          )}
          {showPeople && others.map((who) => (
            <div className="manage-card" key={who.agent}>
              <div className="manage-card-head">
                <span className="manage-card-icon"><UserIcon size={17} /></span>
                <span className="manage-card-label">{who.name || 'Unnamed person'}</span>
                <span className="manage-card-badge">person</span>
              </div>
              <div style={{ margin: '.45rem 0' }}><AddressChip address={who.agent as `0x${string}`} size="sm" /></div>
              {/* A WAY IN, like every organization row has. These cards listed the names and did nothing with
                  them, so the one page that admits you have other names was also the one place you could not
                  go to one. */}
              <p className="manage-card-blurb">
                Another name of yours, with a vault of its own — and never the one your home opens as.{' '}
                <a href={`/as/${who.agent}`}>Act as this name →</a>
              </p>
            </div>
          ))}
          {showOrgs && orgs.length > 0 && <Heading n={orgs.length}>Organizations</Heading>}
          {showOrgs && orgs.map((org) => {
            const t = treasuryFor(org.agent);
            const inactive = orgStatusOf(org) === 'inactive';
            return (
              <div className="manage-card" key={org.agent} style={inactive ? { opacity: 0.72 } : undefined}>
                <div className="manage-card-head">
                  <span className="manage-card-icon"><BuildingIcon size={17} /></span>
                  <span className="manage-card-label">{org.name || 'Unnamed organization'}</span>
                  <span className={`manage-card-badge${inactive ? '' : ' live'}`}>
                    {/* The subclass word (team / circle / church), not the class — a church is an organization, and says which. */}
                    {inactive ? STATUS_LABEL.inactive : orgKindWordOf(org.kind).replace(/^./, (c) => c.toUpperCase())}
                  </span>
                </div>
                <div style={{ margin: '.45rem 0' }}><AddressChip address={org.agent as `0x${string}`} size="sm" /></div>
                <p className="manage-card-blurb">
                  You steward it — your key signs for it. <ExplorerLink address={org.agent} label="explorer ↗" />
                  {onSelect && <> · <button type="button" onClick={() => onSelect(org.agent)} style={{ background: 'none', border: 'none', color: 'var(--color-amber-700)', cursor: 'pointer', padding: 0, minHeight: 0, fontSize: 'inherit' }}>view data →</button></>}
                </p>
                {!org.name && <NameAgentForm agent={org.agent} kind="org" parent={person} person={person} token={token} via={via} onDone={reload} />}
                {inactive && <ActivateOrgRow org={org} person={person} token={token} onDone={reload} />}
                <div style={{ marginTop: '.6rem', paddingTop: '.55rem', borderTop: '1px solid var(--c-g100, #eee)' }}>
                  {t ? (
                    <div style={{ fontSize: '.82rem', display: 'flex', flexDirection: 'column', gap: '.25rem' }}>
                      <span style={{ color: 'var(--c-g500, #64748b)' }}><LandmarkIcon size={13} /> Treasury: <b>{t.name || 'Unnamed'}</b></span>
                      <AddressChip address={t.agent as `0x${string}`} size="sm" />
                      <BalanceLine address={t.agent} refreshKey={version} />
                      {!t.name && <NameAgentForm agent={t.agent} kind="org-treasury" parent={org.agent} person={person} token={token} via={via} onDone={reload} />}
                      <FundForm treasury={t.agent} person={person} via={via} token={token} onDone={reload} />
                    </div>
                  ) : (
                    <CreateAgentForm kind="org-treasury" parent={org.agent} person={person} token={token} via={via} onDone={reload} cta="Create org treasury" />
                  )}
                </div>
                {/* Charter INSIDE this organization — a team, a workspace, a service. The parent is the org,
                    so the child's stewardship grant points at it and its typed name lands under the org's
                    authority. Chartering was only possible from the person's own realm before, which made a
                    team under an organization something you could ask for but not click. */}
                <div style={{ marginTop: '.5rem', paddingTop: '.5rem', borderTop: '1px solid var(--c-g100, #eee)' }}>
                  <CreateAgentForm
                    choices={creatableKinds('org', claimable).filter((c) => c.kind !== 'org-treasury')}
                    parent={org.agent} person={person} token={token} via={via} onDone={reload} cta="Charter inside this organization"
                  />
                </div>
              </div>
            );
          })}

          {/* Every service-class agent you steward — a workspace, a registry, a plain `.svc` service. They
              were invisible here: this page listed org-class agents only, so a service you had chartered
              existed, resolved, and appeared nowhere you could act on it. */}
          {showServices && services.length > 0 && <Heading n={services.length}>Services</Heading>}
          {showServices && services.map((svc) => (
            <div className="manage-card" key={svc.agent}>
              <div className="manage-card-head">
                <span className="manage-card-icon"><LandmarkIcon size={17} /></span>
                <span className="manage-card-label">{svc.name || 'Unnamed service agent'}</span>
                <span className="manage-card-badge live">{KIND_LABEL[svc.kind]}</span>
              </div>
              <div style={{ margin: '.45rem 0' }}><AddressChip address={svc.agent as `0x${string}`} size="sm" /></div>
              <p className="manage-card-blurb">You steward it — your key signs for it. <ExplorerLink address={svc.agent} label="explorer ↗" /></p>
              {/* M06 (398 §4.4) — the fleet boundary on the services roster too: runs at · may spend · holds. */}
              <FleetLines agent={svc.agent as `0x${string}`} token={token} stewardship
                onActivateVault={() => activateVaultIfNeeded(svc.agent as `0x${string}`, via.toLowerCase() as Via, { token })} />
              {!svc.name && <NameAgentForm agent={svc.agent} kind={svc.kind} parent={svc.parent} person={person} token={token} via={via} onDone={reload} />}
            </div>
          ))}

          {/* Charter something new — the kind picker offers every typed root THIS chain has provisioned. */}
          <Heading>Charter a new agent</Heading>
          <div className="manage-card">
            <div className="manage-card-head">
              <span className="manage-card-icon"><BuildingIcon size={17} /></span>
              <span className="manage-card-label">New agent</span>
              <span className="manage-card-badge">new</span>
            </div>
            <p className="manage-card-blurb">An organization, team, workspace or service you control — its own Smart Agent and typed name.</p>
            <CreateAgentForm choices={creatableKinds('person', claimable)} parent={person} person={person} token={token} via={via} onDone={reload} cta="Create agent" />
          </div>
          </>
          )}
        </div>
    </div>
  );
}

// ── /treasuries — every treasury, personal + org ────────────────────────
export function TreasuriesRollup({ token, person, via }: { token: string | null; person: string | null; via: string }) {
  const { agents, loaded, version, reload } = useManagedAgents(token);
  if (!token || !person) return null;
  // ALL of them. A person may hold several — the Ask can charter one in a sentence, and creating
  // alice3.treasury while alice2.treasury existed made the new one vanish from the page that is supposed
  // to list it. Org treasuries were always a list here; personal ones were a single `find`.
  const personal = agents.filter((a) => a.kind === 'person-treasury');
  const orgTreasuries = agents.filter((a) => a.kind === 'org-treasury');
  const orgName = (orgAgent: string) => agents.find((a) => agentClassOf(a.kind) === 'org' && lc(a.agent) === lc(orgAgent))?.name ?? 'organization';

  return (
    <div className="dash-section">
      {!loaded ? (
        // STRUCTURE FIRST (owner, 2026-10-02): the section heading + skeleton cards while the agent tree is out.
        <>
          <div className="ui-section-head"><h2>Treasuries</h2></div>
          <div className="manage-grid"><div style={{ gridColumn: '1 / -1' }}><SkeletonRows rows={2} lead /></div></div>
        </>
      ) : (
        <>
          <div className="ui-section-head"><h2>Personal<span className="ui-count">{personal.length}</span></h2></div>
          <div className="manage-grid">
            {personal.length ? (
              personal.map((t) => (
                <TreasuryCard key={t.agent} name={t.name} address={t.agent}
                  person={person} via={via} token={token} refreshKey={version} onFunded={reload}
                  nameSlot={
                    <>
                      <NameAgentForm agent={t.agent} kind="person-treasury" parent={person} person={person} token={token} via={via} onDone={reload} />
                      {/* WHICH ONE RECEIVES. Holding several is ordinary; only you know which is the one
                          to be paid into, and saying so spares every payer a question about your accounts. */}
                      <PrimaryPayee
                        treasury={t.agent} person={person} token={token}
                        signHash={async (d) => (await signHashFor(via as Via, person as `0x${string}`, { token }))(d)}
                      />
                    </>
                  } />
              ))
            ) : null}
            {/* ALWAYS offered, not only when there are none. Holding one treasury is not a reason to be
                unable to make another: a second is how you separate what is yours from what you are
                holding for something, and an UNNAMED one is how you keep a payment address off the
                public record entirely (spec 338). The card used to appear only in the empty state, so a
                person with one treasury had no way to make a second from the page that lists them. */}
            <div className="manage-card">
              <div className="manage-card-head">
                <span className="manage-card-icon"><LandmarkIcon size={17} /></span>
                <span className="manage-card-label">{personal.length ? 'Another personal treasury' : 'Personal treasury'}</span>
                <span className="manage-card-badge">{personal.length ? 'Optional' : 'Not yet'}</span>
              </div>
              <p className="manage-card-blurb">
                Your own money agent — holds funds and pays on your behalf.
                {' '}An unnamed one is not in the public directory: someone can only pay it if you give them a way to find it.
              </p>
              <CreateAgentForm kind="person-treasury" parent={person} person={person} token={token} via={via} onDone={reload} cta={personal.length ? 'Create another treasury' : 'Create personal treasury'} />
            </div>
          </div>

          <div className="ui-section-head" style={{ marginTop: 'var(--sp-6)' }}><h2>Organization treasuries</h2></div>
          {orgTreasuries.length === 0 ? (
            <p className="manage-card-blurb">No org treasuries yet — create one from an organization in <a href="/agents">Agents</a>.</p>
          ) : (
            <div className="manage-grid">
              {orgTreasuries.map((t) => (
                <TreasuryCard key={t.agent} name={t.name} address={t.agent} sublabel={`${orgName(t.parent)} treasury`}
                  person={person} via={via} token={token} refreshKey={version} onFunded={reload}
                  nameSlot={<NameAgentForm agent={t.agent} kind="org-treasury" parent={t.parent} person={person} token={token} via={via} onDone={reload} />} />
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );
}
