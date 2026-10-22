// Browser orchestration for the real wallet (SIWE) connect → resolve → bootstrap
// → PII, all against the live broker + the deployed demo-a2a worker (via /a2a).
import { AGENT_NAME_PARENT, AGENT_REGISTRY_URN, CLAIMABLE_TLDS, candidateNamesForLabel } from './lib/domain';
import { buildMessage } from '@agenticprimitives/connect-auth/siwe';
import {
  buildSubregistryRegisterCall,
  buildSetPrimaryNameCall,
  buildDeclareAgentTypeCalls,
  agentProfileResolverTypeAbi,
  derivedTypeForTld,
  rootClassForDerivedType,
  isAgentTld,
  buildSetBytes32AttributeCall,
  buildSetAddressAttributeCall,
  buildSetStringAttributeCall,
  namehash,
  PREDICATE_ID,
  CONNECTION_KIND_ID,
  AGENT_KIND_ID,
  type ConnectionKind,
} from '@agenticprimitives/agent-naming';
import {
  buildExecuteCallData,
  buildExecuteBatchCallData,
  AgentAccountClient,
  buildApproveHashCall as buildApproveHashKeyCall,
  readApprovalScheme,
  type ContractCall,
  buildRotationBatch,
  type CredentialRef,
} from '@agenticprimitives/agent-account';
import { buildRevokeDelegationCall, type Delegation } from '@agenticprimitives/delegation';
import {
  buildProposeEdgeCall,
  buildConfirmEdgeCall,
  computeEdgeId,
  RELATIONSHIP_TYPE,
  type RelationshipType,
} from '@agenticprimitives/agent-relationships';
import type { Address, Hex, AdvertisedCapabilityV1 } from '@agenticprimitives/types';
import { getClient } from './lib/oidc-clients';
import { fastPollMs } from './lib/fast-poll';
import { encodeFunctionData, createPublicClient, http, keccak256, toBytes } from 'viem';
import { x402, computeMandateId, type PaymentMandate, type Hex32 } from '@agenticprimitives/payments';
import { connectWallet, connectWalletAccounts, personalSign, rememberHomeEoa, recallHomeEoa, connectedAccountsSilent, rememberSessionCustodian, recallSessionCustodian } from './lib/wallet';
import { registerPasskey, signWithPasskey, signWithDiscoverablePasskey, connectAssertionDiscoverable, loadPasskey, clearPasskey, passkeyRpId, type DemoPasskey } from './lib/passkey';
import { ensureCsrfToken, csrfHeaders } from './csrf';
import { CONTRACTS, CONTRACTS_GENERATION, DEFAULT_RPC_URL, CHAIN, CHAIN_ID, PERMISSIONLESS_SUBREGISTRIES } from './lib/chain';
import { buildRegisterEntryCall, hashBindingProofBody, type RegistryId, type RegistryEntryId } from '@agenticprimitives/registry-kit';
import { hashAgentCard, type AgentCard, agentProfileResolverAbi, buildRegisterProfileCall } from '@agenticprimitives/agent-profile';
import { recordOrgMembership, issueFounderCredential } from './lib/org-membership';
import { filterByLifecycle, filterMyOrgsByLifecycle, type OrgLifecycleStatus, type OrgSurface } from './lib/org-lifecycle';
import { buildApprovedSiteDelegation,
  buildApprovedOperationalIntentDelegation, buildApprovedOrgReadDelegation, issueOrgReadDelegation,
  toWire, type DelegationWire } from './lib/delegation';
import { requestReindex } from './lib/reindex';
import { buildRelatedAgentCredential, relatedAgentProofHash } from '@agenticprimitives/related-agents';
import { demoCustodySignHash, isDemoCustodyHome } from './lib/persona-custody';
// agent-class imports only TYPES from here, so this pair is erased at runtime and cycles nothing.
import { agentClassOf } from './lib/agent-class';

/** A function that signs a 32-byte hash (EOA personal_sign or WebAuthn). */
export type SignHash = (hash: Hex) => Promise<Hex>;

export const AUD = 'demo-sso';

export type SiweOutcome =
  | { status: 'issued'; token: string; address: Address; agent: Address }
  | { status: 'bootstrap'; address: Address }
  | { status: 'disambiguate' | 'rejected'; address?: Address; reason?: string };

async function getNonce(): Promise<string> {
  const r = await fetch('/connect/nonce');
  if (!r.ok) throw new Error('nonce fetch failed');
  return ((await r.json()) as { nonce: string }).nonce;
}

/** Connect a wallet, sign SIWE, resolve to an AgentSession (or signal bootstrap). */
export async function siweLogin(): Promise<SiweOutcome> {
  // Force the wallet account picker — siweLogin is the custodian-CHOOSING sign-in, so the admin picks which
  // account/custodian rather than silently defaulting to the wallet's active one (multi-custodian, spec 266).
  const address = await connectWallet(true);
  const nonce = await getNonce();
  const message = buildMessage({
    domain: window.location.host,
    address,
    uri: window.location.origin,
    chainId: CHAIN_ID,
    nonce,
    statement: 'Sign in to Agentic Connect — proving you control this wallet.',
  });
  const signature = await personalSign(address, message);
  const r = await fetch('/connect/siwe', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ message, signature, aud: AUD }),
  });
  const body = (await r.json()) as { status: string; token?: string; agent?: string; reason?: string };
  if (body.status === 'issued' && body.token) {
    return { status: 'issued', token: body.token, address, agent: (body.agent ?? address) as Address };
  }
  if (body.status === 'bootstrap') return { status: 'bootstrap', address };
  return { status: (body.status as 'disambiguate' | 'rejected') ?? 'rejected', address, reason: body.reason };
}

/** Bootstrap: deploy a person SA (EOA custodian) via demo-a2a, then enroll the facet. */
export async function bootstrapWithWallet(
  address: Address,
  onStep?: (s: string) => void,
  callData?: Hex,
): Promise<{ ok: true; agent: Address } | { ok: false; error: string }> {
  await ensureCsrfToken();
  onStep?.('Preparing your workspace…');
  const buildRes = await fetch('/a2a/session/deploy', {
    method: 'POST',
    credentials: 'include',
    headers: { 'content-type': 'application/json', ...csrfHeaders() },
    // deploy + claim in ONE userOp when callData is supplied (mirror bootstrapWithPasskey) — the server
    // attaches it to the deploy op so the fresh SA runs register+setPrimary in the SAME wallet prompt.
    body: JSON.stringify({ initMethod: 'eoa', owner: address, ...(callData ? { callData } : {}) }),
  });
  if (buildRes.status === 409) {
    return { ok: false, error: 'Gas sponsorship is not enabled on the backend (paymaster).' };
  }
  const built = (await buildRes.json().catch(() => ({}))) as {
    ok?: boolean;
    sender?: Address;
    userOpHash?: Hex;
    userOp?: Record<string, unknown>;
    error?: string;
  };
  if (!buildRes.ok || !built.ok || !built.userOpHash || !built.userOp) {
    return { ok: false, error: built.error ?? `deploy build failed (HTTP ${buildRes.status})` };
  }
  onStep?.('Confirm in your wallet…');
  const signature = await personalSign(address, built.userOpHash);
  onStep?.('Securing on the network…');
  const submitRes = await fetch('/a2a/session/deploy/submit', {
    method: 'POST',
    credentials: 'include',
    headers: { 'content-type': 'application/json', ...csrfHeaders() },
    body: JSON.stringify({ userOp: { ...built.userOp, signature } }),
  });
  const submitted = (await submitRes.json().catch(() => ({}))) as {
    ok?: boolean;
    deployedAddress?: Address;
    error?: string;
    detail?: string;
  };
  if (!submitRes.ok || !submitted.ok || !submitted.deployedAddress) {
    return {
      ok: false,
      error: [submitted.error, submitted.detail].filter(Boolean).join(' — ') || `deploy submit failed (HTTP ${submitRes.status})`,
    };
  }
  const agent = submitted.deployedAddress;
  // No separate enroll step: /connect/siwe derives the SA + records the facet on
  // the reconnect (with a post-deploy poll for RPC lag), so this is just the deploy.
  return { ok: true, agent };
}

/** Execute a call FROM a deployed agent: build userOp -> sign hash -> submit (via /a2a).
 *
 *  The hard part is the nonce. A just-deployed SA consumed nonce 0 in its deploy op, so its
 *  first post-deploy op needs nonce 1 — but the relayer's `getNonce` read can lag and return
 *  0, producing `AA25 invalid account nonce` (the wrong nonce is baked into the signature, so
 *  resubmitting the same op can't fix it). `minNonce` gates this: we poll the BUILD (no
 *  signing — no credential prompt) until the relayer's view reaches the expected nonce, THEN
 *  sign ONCE and submit. So we never sign a stale-nonce op, and the passkey/wallet is prompted
 *  exactly once. If a submit still fails (residual simulation lag, or an unexpected AA25), we
 *  rebuild+resign on the next loop with a fresh nonce. */
async function executeCall(
  sender: Address,
  signHash: SignHash,
  callData: Hex,
  opts: { minNonce?: bigint; attempts?: number } = {},
): Promise<{ ok: true; txHash?: Hex } | { ok: false; error: string }> {
  const { minNonce, attempts = 4 } = opts;
  await ensureCsrfToken();
  let lastErr = 'execute failed';

  for (let i = 0; i < attempts; i++) {
    if (i > 0) await new Promise((r) => setTimeout(r, fastPollMs(2500)));

    // Build (no signing yet → no credential prompt on this step).
    const buildRes = await fetch('/a2a/account/build-call-userop', {
      method: 'POST',
      credentials: 'include',
      headers: { 'content-type': 'application/json', ...csrfHeaders() },
      body: JSON.stringify({ sender, callData }),
    });
    const b = (await buildRes.json().catch(() => ({}))) as {
      ok?: boolean;
      userOpHash?: Hex;
      userOp?: (Record<string, unknown> & { nonce?: string });
      error?: string;
      detail?: string;
    };
    if (!buildRes.ok || !b.ok || !b.userOpHash || !b.userOp) {
      lastErr = [b.error, b.detail].filter(Boolean).join(' — ') || `build-call failed (HTTP ${buildRes.status})`;
      continue;
    }

    // Nonce gate: don't sign until the relayer's nonce view reflects the deploy.
    if (minNonce !== undefined && BigInt(b.userOp.nonce ?? '0') < minNonce) {
      lastErr = `relayer nonce ${b.userOp.nonce} < ${minNonce} — deploy not yet propagated`;
      continue; // rebuild next loop; still no prompt
    }

    // Sign ONCE for this (correct-nonce) op, then submit.
    const signature = await signHash(b.userOpHash);
    const submitRes = await fetch('/a2a/account/submit-call-userop', {
      method: 'POST',
      credentials: 'include',
      headers: { 'content-type': 'application/json', ...csrfHeaders() },
      body: JSON.stringify({ userOp: { ...b.userOp, signature } }),
    });
    const submitted = (await submitRes.json().catch(() => ({}))) as { ok?: boolean; transactionHash?: Hex; error?: string; detail?: string };
    if (submitRes.ok && submitted.ok) return { ok: true, txHash: submitted.transactionHash };
    lastErr =
      [submitted.error, submitted.detail].filter(Boolean).join(' — ') || `submit-call failed (HTTP ${submitRes.status})`;
  }
  return { ok: false, error: lastErr };
}

const PAY_EXECUTE_ABI = [{ type: 'function', name: 'execute', stateMutability: 'nonpayable', inputs: [{ name: 'target', type: 'address' }, { name: 'value', type: 'uint256' }, { name: 'data', type: 'bytes' }], outputs: [] }] as const;
const PAY_USDC_ABI = [
  { type: 'function', name: 'balanceOf', stateMutability: 'view', inputs: [{ name: 'a', type: 'address' }], outputs: [{ type: 'uint256' }] },
  { type: 'function', name: 'mint', stateMutability: 'nonpayable', inputs: [{ name: 'to', type: 'address' }, { name: 'amount', type: 'uint256' }], outputs: [] },
] as const;

/** Demo funding, ALL-CUSTODIAN: if the person-treasury holds less than `need` mock USDC, the person SA
 *  mints a top-up to it (MockUSDC.mint is permissionless), signed by the SAME credential (signHash) and
 *  gasless via executeCall. No SIWE-only window.ethereum, no service faucet, no held key. Non-fatal. */
async function fundTreasuryIfNeeded(personSa: Address, treasury: Address, asset: Address, need: bigint, signHash: SignHash): Promise<void> {
  try {
    const pc = createPublicClient({ chain: CHAIN, transport: http(DEFAULT_RPC_URL) });
    const bal = (await pc.readContract({ address: asset, abi: PAY_USDC_ABI, functionName: 'balanceOf', args: [treasury] })) as bigint;
    if (bal >= need) return;
    const topUp = need > 1_000_000n ? need * 4n : 1_000_000n; // a generous buffer so it rarely re-mints
    const mintData = encodeFunctionData({ abi: PAY_USDC_ABI, functionName: 'mint', args: [treasury, topUp] });
    const fundCall = encodeFunctionData({ abi: PAY_EXECUTE_ABI, functionName: 'execute', args: [asset, 0n, mintData] });
    await executeCall(personSa, signHash, fundCall);
  } catch { /* non-fatal — the redemption fails loudly if truly underfunded */ }
}

/** spec 272 — charge an x402 payment IN the connect ceremony, ALL-CUSTODIAN. `signHash` is the same
 *  wallet/passkey/KMS signer (`signHashFor`) the ceremony already uses; the reader's person SA executes
 *  the redemption of its just-minted `person-treasury → payee` payment delegation (OPEN delegate → the
 *  payer redeems, push), gaslessly via executeCall. The PaymentEnforcer moves `amount` USDC
 *  person-treasury → payee. Returns the on-chain settlement tx hash — the relying app verifies it +
 *  mints an N-read pass. No held key: the reader's own credential signs, the paymaster sponsors gas. */
export async function chargePayment(
  personSa: Address,
  delegation: unknown,
  signHash: SignHash,
  opts: { payee: Address; asset: Address; amount: bigint; edition: string },
): Promise<{ ok: true; settlementHash: Hex } | { ok: false; error: string }> {
  const deleg = delegation as { delegator?: Address };
  if (!deleg?.delegator) return { ok: false, error: 'payment delegation missing delegator' };
  const payer = deleg.delegator;
  // Uniform funding (all custodians): top up the person-treasury if it can't cover this charge.
  await fundTreasuryIfNeeded(personSa, payer, opts.asset, opts.amount, signHash);
  const nonce = BigInt(Date.now());
  const now = Math.floor(Date.now() / 1000);
  const zero32 = ('0x' + '00'.repeat(32)) as Hex32;
  const asset = { id: opts.asset, symbol: 'USDC', decimals: 6 };
  const resourceHash = keccak256(toBytes(`x402:${opts.edition}:pass`)) as Hex32;
  const mandate = {
    mandateId: computeMandateId({ payer, nonce, rail: 'x402', chain: CHAIN_ID }),
    payer, payee: opts.payee, granter: payer, rail: 'x402',
    amountPolicy: { kind: 'exact', amount: opts.amount, asset, chain: CHAIN_ID },
    nonce, maxRedemptions: 1, validFrom: now, expiresAt: now + 3600,
    contextBinding: { resource: { method: 'GET', url: `x402:${opts.edition}:pass`, requestBodyHash: zero32 }, chain: CHAIN_ID, asset, nonce, validFrom: now, expiresAt: now + 3600 },
    mode: 'closed', reasonHash: keccak256(toBytes(`access:${opts.edition}`)) as Hex32, signature: '0x',
  } as PaymentMandate;
  const plan = x402.buildRedemptionCalldata({
    mandate, delegation: delegation as never,
    delegationManager: CONTRACTS.delegationManager, paymentEnforcer: CONTRACTS.paymentEnforcer,
    asset: opts.asset, resourceHash,
  });
  const callData = encodeFunctionData({ abi: PAY_EXECUTE_ABI, functionName: 'execute', args: [plan.to, plan.value, plan.data] });
  const res = await executeCall(personSa, signHash, callData);
  if (!res.ok) return { ok: false, error: res.error };
  if (!res.txHash) return { ok: false, error: 'redemption submitted but no settlement tx hash' };
  return { ok: true, settlementHash: res.txHash };
}

/** spec 272 recurring — the PULL-side mirror of chargePayment, for OWNER-online subscription collection.
 *  The collection `treasury` (= the payee, e.g. lbsb-treasury.impact) is the delegate of the subscriber's
 *  standing pull mandate, so IT is the redeemer: the owner (its custodian) signs `executeCall(treasury, …)`
 *  via signHashFor — same all-custodian signer, no held key. The PaymentEnforcer moves `amount` USDC
 *  payer-treasury → treasury, capped by the mandate's caveats. Returns the settlement tx hash per mandate. */
export async function collectPayment(
  treasury: Address,
  pullDelegation: unknown,
  signHash: SignHash,
  opts: { asset: Address; amount: bigint; edition: string },
): Promise<{ ok: true; settlementHash: Hex } | { ok: false; error: string }> {
  const deleg = pullDelegation as { delegator?: Address; delegate?: Address };
  if (!deleg?.delegator) return { ok: false, error: 'pull delegation missing delegator' };
  if (deleg.delegate && deleg.delegate.toLowerCase() !== treasury.toLowerCase())
    return { ok: false, error: 'pull delegation delegate ≠ collection treasury' };
  const payer = deleg.delegator; // the subscriber's person-treasury (funds come FROM here)
  // Demo convenience: ensure the subscriber's treasury can cover this period (mock USDC mint, permissionless),
  // signed by the same owner credential. A real deployment would require the subscriber to maintain balance.
  await fundTreasuryIfNeeded(treasury, payer, opts.asset, opts.amount, signHash);
  const nonce = BigInt(Date.now());
  const now = Math.floor(Date.now() / 1000);
  const zero32 = ('0x' + '00'.repeat(32)) as Hex32;
  const asset = { id: opts.asset, symbol: 'USDC', decimals: 6 };
  const resourceHash = keccak256(toBytes(`x402:${opts.edition}:subscription`)) as Hex32;
  const mandate = {
    mandateId: computeMandateId({ payer, nonce, rail: 'x402', chain: CHAIN_ID }),
    payer, payee: treasury, granter: payer, rail: 'x402',
    amountPolicy: { kind: 'exact', amount: opts.amount, asset, chain: CHAIN_ID },
    nonce, maxRedemptions: 1, validFrom: now, expiresAt: now + 3600,
    contextBinding: { resource: { method: 'GET', url: `x402:${opts.edition}:subscription`, requestBodyHash: zero32 }, chain: CHAIN_ID, asset, nonce, validFrom: now, expiresAt: now + 3600 },
    mode: 'closed', reasonHash: keccak256(toBytes(`subscription:${opts.edition}`)) as Hex32, signature: '0x',
  } as PaymentMandate;
  const plan = x402.buildRedemptionCalldata({
    mandate, delegation: pullDelegation as never,
    delegationManager: CONTRACTS.delegationManager, paymentEnforcer: CONTRACTS.paymentEnforcer,
    asset: opts.asset, resourceHash,
  });
  const callData = encodeFunctionData({ abi: PAY_EXECUTE_ABI, functionName: 'execute', args: [plan.to, plan.value, plan.data] });
  const res = await executeCall(treasury, signHash, callData);
  if (!res.ok) return { ok: false, error: res.error };
  if (!res.txHash) return { ok: false, error: 'collection submitted but no settlement tx hash' };
  return { ok: true, settlementHash: res.txHash };
}

/** spec 272 recurring — OWNER-online subscription collection, end to end. Fetches the DUE batch from the
 *  content service (a2a, owner-gated by `idToken`), redeems each subscriber's standing pull mandate as the
 *  collection `treasury` (signed by the owner credential — no held key), then posts the settlements back so
 *  the service advances each period + mints the next pass. One owner ceremony bills every due subscriber. */
export async function collectSubscriptions(opts: {
  treasury: Address;
  asset: Address;
  edition: string;
  a2aBase: string;
  idToken: string;
  signHash: SignHash;
  onStep?: (s: string) => void;
}): Promise<{ ok: boolean; attempted: number; collected: number; results: Array<{ subscriptionId?: number; subject?: string; ok: boolean; settlementHash?: Hex; error?: string }>; error?: string }> {
  const base = opts.a2aBase.replace(/\/$/, '');
  opts.onStep?.('Finding subscriptions due for renewal…');
  const dueRes = await fetch(`${base}/admin/subscriptions/due`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ id_token: opts.idToken, edition: opts.edition }),
  }).then((r) => r.json()).catch(() => ({ ok: false, error: 'due-list request failed' })) as { ok?: boolean; due?: Array<{ id?: number; subject?: string; amount_per_period?: string; pull_mandate?: unknown }>; error?: string };
  if (!dueRes.ok) return { ok: false, attempted: 0, collected: 0, results: [], error: dueRes.error ?? 'could not list due subscriptions' };
  const due = dueRes.due ?? [];
  const results: Array<{ subscriptionId?: number; subject?: string; ok: boolean; settlementHash?: Hex; error?: string }> = [];
  for (let i = 0; i < due.length; i++) {
    const d = due[i]!;
    opts.onStep?.(`Charging subscription ${i + 1}/${due.length}…`);
    if (!d.pull_mandate) { results.push({ subscriptionId: d.id, subject: d.subject, ok: false, error: 'no pull mandate stored' }); continue; }
    const amount = (() => { try { return BigInt(d.amount_per_period ?? '0'); } catch { return 0n; } })();
    if (amount <= 0n) { results.push({ subscriptionId: d.id, subject: d.subject, ok: false, error: 'invalid amount' }); continue; }
    const r = await collectPayment(opts.treasury, d.pull_mandate, opts.signHash, { asset: opts.asset, amount, edition: opts.edition });
    if (r.ok) results.push({ subscriptionId: d.id, subject: d.subject, ok: true, settlementHash: r.settlementHash });
    else results.push({ subscriptionId: d.id, subject: d.subject, ok: false, error: r.error });
  }
  const settled = results.filter((x) => x.ok && x.settlementHash).map((x) => ({ subscriptionId: x.subscriptionId, subject: x.subject, settlementHash: x.settlementHash }));
  if (settled.length) {
    opts.onStep?.('Recording settlements + renewing periods…');
    await fetch(`${base}/admin/subscriptions/collected`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ id_token: opts.idToken, edition: opts.edition, results: settled }),
    }).catch(() => undefined);
  }
  return { ok: true, attempted: due.length, collected: settled.length, results };
}

/** Read-only ABIs for the one-name-per-caller guard below. */
const SUBREG_CLAIMED_ABI = [
  { type: 'function', name: 'claimedBy', stateMutability: 'view', inputs: [{ name: '', type: 'address' }], outputs: [{ type: 'bytes32' }] },
] as const;
const PRIMARY_NAME_ABI = [
  { type: 'function', name: 'primaryName', stateMutability: 'view', inputs: [{ name: '', type: 'address' }], outputs: [{ type: 'bytes32' }] },
] as const;
const RESOLVER_NAMEOF_ABI = [
  { type: 'function', name: 'nameOf', stateMutability: 'view', inputs: [{ name: '', type: 'bytes32' }], outputs: [{ type: 'string' }] },
] as const;

/** spec 346 — the subregistry a claim goes through: the legacy parent's (default) or the typed suffix's
 *  (from the deployment's `permissionlessSubregistries` map). A typed suffix this deployment cannot claim
 *  is an error, never a silent fall-back to `.impact` (ADR-0013). */
function subregistryForTld(tld: string | undefined): { ok: true; subregistry: Address; typed: boolean } | { ok: false; error: string } {
  if (!tld || tld === AGENT_NAME_PARENT) return { ok: true, subregistry: CONTRACTS.permissionlessSubregistry, typed: false };
  const a = isAgentTld(tld) ? PERMISSIONLESS_SUBREGISTRIES[tld] : undefined;
  if (!a) return { ok: false, error: `".${tld}" is not claimable on this deployment` };
  return { ok: true, subregistry: a, typed: true };
}

/** Which roots this SA has ALREADY claimed under, and the name it holds in each.
 *
 *  `PermissionlessSubregistry.claimedBy` is write-once and has no release: an SA gets exactly one label
 *  per root, forever. So "rename" cannot mean "take a different label under the same suffix" — that
 *  reverts `AlreadyClaimed`. It means claim under a suffix this agent has not used yet, and point the
 *  primary name at it. This read is what lets the UI offer only the suffixes that can actually work,
 *  instead of finding out on-chain after the member has typed a name.
 */
export async function readClaimedRoots(
  agent: Address,
): Promise<Array<{ tld: string; node: Hex; name: string | null; typed: boolean }>> {
  const roots: Array<{ tld: string; subregistry: Address; typed: boolean }> = [
    { tld: AGENT_NAME_PARENT, subregistry: CONTRACTS.permissionlessSubregistry, typed: false },
    ...Object.entries(PERMISSIONLESS_SUBREGISTRIES)
      .filter((e): e is [string, Address] => !!e[1])
      .map(([tld, subregistry]) => ({ tld, subregistry, typed: true })),
  ];
  const pc = createPublicClient({ chain: CHAIN, transport: http(DEFAULT_RPC_URL) });
  const out: Array<{ tld: string; node: Hex; name: string | null; typed: boolean }> = [];
  await Promise.all(roots.map(async (r) => {
    let node: Hex;
    try {
      node = (await pc.readContract({ address: r.subregistry, abi: SUBREG_CLAIMED_ABI, functionName: 'claimedBy', args: [agent] })) as Hex;
    } catch {
      return; // a root this deployment lists but cannot read is reported as unclaimed, never as claimed
    }
    if (!node || BigInt(node) === 0n) return;
    let name: string | null = null;
    try {
      name = (await pc.readContract({ address: CONTRACTS.agentNameUniversalResolver, abi: RESOLVER_NAMEOF_ABI, functionName: 'nameOf', args: [node] })) as string;
    } catch { /* the claim is the fact; the label is a nicety */ }
    out.push({ tld: r.tld, node, name: name || null, typed: r.typed });
  }));
  return out.sort((a, b) => a.tld.localeCompare(b.tld));
}

/** The node this SA currently presents as its name (`primaryName`), or null when it presents none. */
export async function readPrimaryNameNode(agent: Address): Promise<Hex | null> {
  const pc = createPublicClient({ chain: CHAIN, transport: http(DEFAULT_RPC_URL) });
  const node = (await pc.readContract({
    address: CONTRACTS.agentNameRegistry, abi: PRIMARY_NAME_ABI, functionName: 'primaryName', args: [agent],
  })) as Hex;
  return node && BigInt(node) !== 0n ? node : null;
}

/** Point this SA's public name at `node`, or clear it entirely with `null`.
 *
 *  Clearing is the only "reset" the naming contracts offer: `setPrimaryName(0)` drops the reverse record
 *  so the agent presents no name. It does NOT release the label — the forward record still resolves to
 *  this agent and the root still counts it as claimed. Saying otherwise would promise a rollback the
 *  chain cannot perform.
 */
export async function setPrimaryName(
  agent: Address,
  signHash: SignHash,
  node: Hex | null,
): Promise<{ ok: true } | { ok: false; error: string }> {
  const call = buildSetPrimaryNameCall({
    registry: CONTRACTS.agentNameRegistry,
    node: node ?? (`0x${'0'.repeat(64)}` as Hex),
  });
  const res = await executeCalls(agent, signHash, [call]);
  return res.ok ? { ok: true } : { ok: false, error: res.error };
}

/** spec 346 §3.6 step 1b — declare the derived type on the SA's profile subject BEFORE a typed claim, so the
 *  suffix ↔ record invariant holds from the first block. Reads `isRegistered` once (the setters require it). */
async function declareTypeCalls(sa: Address, tld: string, serviceRole?: string): Promise<ContractCall[]> {
  if (!isAgentTld(tld)) return [];
  const pc = createPublicClient({ chain: CHAIN, transport: http(DEFAULT_RPC_URL) });
  const registered = (await pc.readContract({ address: CONTRACTS.agentProfileResolver, abi: agentProfileResolverTypeAbi, functionName: 'isRegistered', args: [sa] })) as boolean;
  return buildDeclareAgentTypeCalls({ profileResolver: CONTRACTS.agentProfileResolver, agent: sa, agentType: derivedTypeForTld(tld), serviceRole, registered });
}

/** spec 346 — the typed suffix an app-level kind claims under, IF this deployment lists it as claimable;
 *  otherwise `undefined` = the legacy parent. Kinds map DOWN to a derived type (ADR-0046/0061): org, circle and
 *  church are Organizations; team → Team; workspace → WorkspaceAgent; both treasuries → Treasury. */
export function typedTldForKind(kind: AgentKind | 'person'): { tld: string; serviceRole?: string } | undefined {
  const map: Record<string, { tld: string; serviceRole?: string }> = {
    person: { tld: 'me' }, org: { tld: 'org' }, circle: { tld: 'circle' }, church: { tld: 'church' }, household: { tld: 'household' }, team: { tld: 'team' },
    workspace: { tld: 'workspace', serviceRole: 'workspace' }, 'person-treasury': { tld: 'treasury' }, 'org-treasury': { tld: 'treasury' },
    service: { tld: 'svc', serviceRole: 'service' },
  };
  const t = map[kind];
  return t && CLAIMABLE_TLDS.includes(t.tld) ? t : undefined;
}

/** The home an EXISTING subdomain label denotes: the first of `candidateNamesForLabel(label)` (typed-first, then
 *  the legacy root) that resolves to an agent. `null` when none does — the label is free. One lookup over an
 *  ordered candidate set whose uniqueness `/connect/name` enforces (spec 346 migration), not a fallback. */
export async function resolveHomeNameForLabel(label: string): Promise<{ name: string; agent: Address } | null> {
  for (const name of candidateNamesForLabel(label)) {
    const info = (await (await fetch(`/connect/name-info?name=${encodeURIComponent(name)}`)).json().catch(() => ({}))) as { agent?: Address | null };
    if (info.agent && BigInt(info.agent) !== 0n) return { name, agent: info.agent };
  }
  return null;
}

export interface TypedClaimOpts {
  /** A typed suffix (spec 346). Omit for the deployment's legacy parent. */
  tld?: string;
  /** Required = the type name for `.workspace` / `.registry`; free for other services. */
  serviceRole?: string;
}

/** Claim a forced-unique `<base>[N].impact` for the agent + set it as primary.
 *  register + setPrimaryName are BATCHED into one execute UserOp (one nonce, one signature):
 *  they must land together, and the batch avoids an inter-userOp race where the second op
 *  sees a stale view of the first's state. `minNonce` rides out the post-deploy nonce lag
 *  (pass the nonce the SA must be at after its deploy, e.g. 1n right after a fresh deploy).
 *
 *  ONE-NAME-PER-CALLER GUARD: PermissionlessSubregistry.register reverts `AlreadyClaimed` if THIS SA
 *  already claimed a name (spec 257). A reconnected/existing home already HAS its name, so re-claiming a
 *  DIFFERENT one (e.g. founding a second, differently-named home with a wallet that already has one) would
 *  revert the whole userOp → a 500 the founding flow can't recover from. We detect the existing claim and
 *  return it as a NO-OP success instead — the home keeps its established name (one mechanism, ADR-0013: a
 *  positive `claimedBy` read IS the answer; we don't attempt-then-handle-the-revert). */
/** The root a PERSON's name is claimed under on this deployment — `.me` where the typed roots exist,
 *  the legacy parent otherwise. It is the DEFAULT rather than a parameter every caller must remember,
 *  because forgetting it is silent: the claim succeeds, under the wrong root, and the agent ends up with
 *  no derived type (spec 346) — which only surfaces much later as "declare its type before projecting".
 *  Three of the four person-claim call sites had forgotten it. */
function personClaimRoot(): TypedClaimOpts {
  return CLAIMABLE_TLDS.includes('me') ? { tld: 'me' } : {};
}

export async function claimName(
  agent: Address,
  signHash: SignHash,
  base: string,
  onStep?: (s: string) => void,
  minNonce?: bigint,
  /** Defaults to this deployment's PERSON root; a managed agent passes its own via `typedTldForKind`. */
  typed: TypedClaimOpts = personClaimRoot(),
  // `alreadyClaimed` is NOT decoration: this root gives an SA one label forever, so a second claim is a
  // silent no-op that returns the OLD name. A rename screen reporting that as success would tell the
  // member their name changed when nothing happened.
): Promise<{ ok: true; name: string; alreadyClaimed?: boolean } | { ok: false; error: string }> {
  const sub = subregistryForTld(typed.tld);
  if (!sub.ok) return { ok: false, error: sub.error };
  // Already-claimed? Surface the existing name; never submit a reverting register.
  try {
    const pc = createPublicClient({ chain: CHAIN, transport: http(DEFAULT_RPC_URL) });
    const prior = (await pc.readContract({
      address: sub.subregistry, abi: SUBREG_CLAIMED_ABI, functionName: 'claimedBy', args: [agent],
    })) as Hex;
    if (prior && BigInt(prior) !== 0n) {
      let existing = '';
      try {
        existing = (await pc.readContract({
          address: CONTRACTS.agentNameUniversalResolver, abi: RESOLVER_NAMEOF_ABI, functionName: 'nameOf', args: [prior],
        })) as string;
      } catch { /* resolver read failed — still a no-op claim, just without the resolved label */ }
      // The label is already this agent's and cannot be re-claimed, but it may not be the one the agent
      // PRESENTS — clearing the public name leaves the claim intact and the pointer empty. Re-point it,
      // because otherwise this branch reports a name the agent does not answer to and changes nothing.
      let restored = false;
      try {
        const current = (await pc.readContract({
          address: CONTRACTS.agentNameRegistry, abi: PRIMARY_NAME_ABI, functionName: 'primaryName', args: [agent],
        })) as Hex;
        if (!current || current.toLowerCase() !== prior.toLowerCase()) {
          onStep?.(existing ? `Presenting ${existing} again…` : 'Presenting your name again…');
          const re = await executeCalls(agent, signHash, [
            buildSetPrimaryNameCall({ registry: CONTRACTS.agentNameRegistry, node: prior }),
          ]);
          if (!re.ok) return { ok: false, error: `could not present the held name: ${re.error}` };
          restored = true;
          requestReindex([agent]);
        }
      } catch (e) {
        return { ok: false, error: `could not read or set the public name: ${String((e as Error)?.message ?? e)}` };
      }
      onStep?.(existing ? `This agent's name is ${existing}.` : 'This agent already holds a name.');
      return { ok: true, name: existing || base, alreadyClaimed: !restored };
    }
  } catch { /* read failed → fall through and attempt the claim (the on-chain AlreadyClaimed guard still protects) */ }

  onStep?.('Finding a free name…');
  const nameRes = await fetch(`/connect/name?base=${encodeURIComponent(base)}${typed.tld ? `&tld=${encodeURIComponent(typed.tld)}` : ''}`);
  const picked = (await nameRes.json()) as { label?: string; name?: string; node?: Hex; error?: string };
  if (!nameRes.ok || !picked.name || !picked.node || !picked.label) {
    return { ok: false, error: picked.error ?? 'no free name' };
  }

  onStep?.(`Claiming ${picked.name}…`);
  const register = buildSubregistryRegisterCall({
    subregistry: sub.subregistry,
    label: picked.label,
    newOwner: agent,
  });
  const setPrimary = buildSetPrimaryNameCall({ registry: CONTRACTS.agentNameRegistry, node: picked.node });
  // Typed claim: declare the derived type first (step 1b); the name record's agentKind is the ROOT of that type.
  const declare = sub.typed ? await declareTypeCalls(agent, typed.tld!, typed.serviceRole) : [];
  const agentKind = sub.typed ? rootClassForDerivedType(derivedTypeForTld(typed.tld as never)) : 'person';
  const batch = buildExecuteBatchCallData([...declare, register, setPrimary, ...buildNameRecordCalls(picked.node, agent, { agentKind })]);
  const res = await executeCall(agent, signHash, batch, { minNonce, attempts: 10 });
  if (!res.ok) return { ok: false, error: `name claim failed: ${res.error}` };
  requestReindex([agent]); // auto-index: surface the freshly-named agent in discovery immediately
  return { ok: true, name: picked.name };
}

// ── Passkey (WebAuthn) ──────────────────────────────────────────────
export type { DemoPasskey };
export type PasskeyOutcome =
  | { status: 'issued'; token: string; passkey: DemoPasskey }
  | { status: 'bootstrap'; passkey: DemoPasskey }
  | { status: 'disambiguate' | 'rejected'; passkey?: DemoPasskey; reason?: string };

/** A signHash backed by the ROOT passkey.
 *
 * Local-first for signing ceremonies: when this browser has the credential id cached, use an
 * allowCredentials assertion with that exact id. On Windows this goes straight to the local platform
 * authenticator instead of the cross-device phone picker. If the cache is absent, use a discoverable
 * assertion with the WebAuthn `client-device` hint so a Windows Hello passkey that exists on this machine
 * can still sign; after that assertion we cache the credential id for the next local-fast call.
 */
export const passkeySignHash: SignHash = (hash) => {
  const cached = loadPasskey();
  return cached ? signWithPasskey(hash) : signWithDiscoverablePasskey(hash, undefined, { preferLocalDevice: true });
};

// ── Google × KMS custody (spec 235): the server signs with the per-subject custodian ──
//
// A Google-only member never holds a key. demo-a2a derives their per-(iss,sub) custodian
// C_sub and signs on their behalf, gated by the custody session (verified vs the broker
// JWKS). So securing a home + giving permission are SERVER round-trips, not device gestures —
// their only gesture was signing in with Google.

/**
 * A custody call through the Home's `/a2a` pass-through (a Vercel rewrite to the runtime), retried when the
 * PASS-THROUGH failed rather than the runtime answering (GC load test, 2026-10-20).
 *
 * With five people signing up at once on staging, two were left on the code screen reading
 * "secure-home failed (HTTP 502)": a 502 with no body, while the runtime recorded the caller hanging up and
 * no error of its own. Nothing retried it, so a person was stranded. A 502/503/504 that carries the
 * runtime's own JSON error is the runtime's answer and is returned as is; a bare gateway failure or a
 * dropped connection is tried again, up to `attempts` times, a little later each time.
 *
 * ONLY for calls that are safe to repeat: signing a hash, bootstrapping the email/OIDC home (its address is
 * fixed by the identity), reading the custodian. Not for org creation or a name claim, where a repeat of a
 * success whose answer was lost could make a second one.
 */
async function custodyFetch(url: string, init: RequestInit, attempts = 3): Promise<Response> {
  let lastResponse: Response | null = null;
  let lastError: unknown = null;
  for (let i = 0; i < attempts; i += 1) {
    if (i > 0) await new Promise((r) => setTimeout(r, 1500 * i));
    try {
      const res = await fetch(url, init);
      if (![502, 503, 504].includes(res.status)) return res;
      const text = await res.clone().text().catch(() => '');
      if (/^\s*\{[\s\S]*"error"/.test(text)) return res; // the runtime's own answer, not the pass-through's
      lastResponse = res;
      console.warn(`[custody] ${url} answered ${res.status} with no error of its own — trying again (${i + 1}/${attempts})`);
    } catch (e) {
      lastError = e;
      console.warn(`[custody] ${url} did not answer — trying again (${i + 1}/${attempts})`, e);
    }
  }
  if (lastResponse) return lastResponse;
  throw lastError instanceof Error ? lastError : new Error(`${url} did not answer`);
}

/** A SignHash that has demo-a2a sign a digest with the member's KMS custodian. The custody
 *  session proves the member; demo-a2a derives C_sub + signs for `sender` (their SA). */
export function googleSignHash(sender: Address, sessionToken: string): SignHash {
  return async (hash: Hex): Promise<Hex> => {
    await ensureCsrfToken();
    const res = await custodyFetch('/a2a/custody/oidc/sign', {
      method: 'POST',
      credentials: 'include',
      headers: { 'content-type': 'application/json', ...csrfHeaders() },
      body: JSON.stringify({ session: sessionToken, hash, sender }),
    });
    const body = (await res.json().catch(() => ({}))) as { ok?: boolean; signature?: Hex; error?: string; detail?: string };
    if (!res.ok || !body.ok || !body.signature) {
      // A login-grade session (email/phone code on a home the code doesn't custody) can't drive the KMS
      // signer — demo-a2a's custody gate 403s. Say what to DO, not just what failed.
      if (res.status === 403 && /not oidc|custody-grade|onchain-confirmed/i.test(body.error ?? '')) {
        throw new Error('Your current sign-in can\u2019t authorize this. Sign out, then sign in again with the method that secures your account (or re-enter your code) and retry.');
      }
      throw new Error([body.error, body.detail].filter(Boolean).join(' — ') || `custody sign failed (HTTP ${res.status})`);
    }
    return body.signature;
  };
}

/** Secure a home for a Google-only member: pick a free name, then have demo-a2a deploy their
 *  KMS-custodied SA + claim the name in ONE server-signed, sponsored userOp. */
export async function secureHomeWithGoogle(
  sessionToken: string,
  base: string,
  onStep?: (s: string) => void,
): Promise<{ ok: true; agent: Address; name: string } | { ok: false; error: string }> {
  onStep?.('Finding a free name…');
  // spec 346 — a person's home claims the PERSON root (`.me` where claimable), not the legacy parent.
  const typed = personClaimRoot();
  const picked = (await (await fetch(`/connect/name?base=${encodeURIComponent(base)}${typed.tld ? `&tld=${encodeURIComponent(typed.tld)}` : ''}`)).json()) as {
    label?: string;
    name?: string;
    node?: Hex;
    error?: string;
  };
  if (!picked.label || !picked.name || !picked.node) return { ok: false, error: picked.error ?? 'no free name' };
  onStep?.('Securing your home on the network…');
  await ensureCsrfToken();
  const res = await fetch('/a2a/custody/oidc/bootstrap-and-claim', {
    method: 'POST',
    credentials: 'include',
    headers: { 'content-type': 'application/json', ...csrfHeaders() },
    body: JSON.stringify({ session: sessionToken, label: picked.label, node: picked.node, tld: typed.tld }),
  });
  const body = (await res.json().catch(() => ({}))) as { ok?: boolean; agent?: Address; name?: string; error?: string; detail?: string };
  if (!res.ok || !body.ok || !body.agent) {
    return { ok: false, error: [body.error, body.detail].filter(Boolean).join(' — ') || `secure-home failed (HTTP ${res.status})` };
  }
  try {
    const wr = await executeCalls(body.agent, googleSignHash(body.agent, sessionToken), buildNameRecordCalls(picked.node, body.agent, { agentKind: 'person' }));
    if (!wr.ok) console.warn('[secure-home] public naming metadata write failed:', wr.error);
  } catch (e) {
    console.warn('[secure-home] public naming metadata write failed:', e);
  }
  return { ok: true, agent: body.agent, name: body.name ?? picked.name };
}

/** spec 257 Phase 1.5 — TRUE name-deferral. Secure a home for a Google-only member with NO
 *  name: demo-a2a deploys their KMS-custodied SA with empty callData in one sponsored userOp,
 *  leaving the member's single subregistry slot FREE. The public name is claimed LATER, by the
 *  member's choice, via {@link claimName} (signed by the same C_sub through /custody/google/sign).
 *  Onboarding stays name-free; the SA resolves deterministically from the Google identity. */
export async function secureHomeGoogleNoName(
  sessionToken: string,
  onStep?: (s: string) => void,
): Promise<{ ok: true; agent: Address } | { ok: false; error: string }> {
  onStep?.('Securing your home on the network…');
  await ensureCsrfToken();
  const res = await custodyFetch('/a2a/custody/oidc/bootstrap', {
    method: 'POST',
    credentials: 'include',
    headers: { 'content-type': 'application/json', ...csrfHeaders() },
    body: JSON.stringify({ session: sessionToken }),
  });
  const body = (await res.json().catch(() => ({}))) as { ok?: boolean; agent?: Address; error?: string; detail?: string };
  if (!res.ok || !body.ok || !body.agent) {
    return { ok: false, error: [body.error, body.detail].filter(Boolean).join(' — ') || `secure-home failed (HTTP ${res.status})` };
  }
  return { ok: true, agent: body.agent };
}

/** Sign in with a passkey (registering one first if none on this device), then resolve. */
export async function passkeyLogin(registerIfMissing = true): Promise<PasskeyOutcome> {
  let passkey = loadPasskey();
  if (!passkey) {
    if (!registerIfMissing) return { status: 'rejected', reason: 'no passkey on this device' };
    passkey = await registerPasskey('Agentic Connect passkey');
  }
  const { challenge } = (await (await fetch('/connect/passkey-challenge')).json()) as { challenge: Hex };
  let signature: Hex;
  try {
    signature = await signWithPasskey(challenge);
  } catch (e) {
    // The cached credential id is present in THIS origin's localStorage but no longer usable on the
    // device's authenticator (rotated/cleared Windows Hello, a different device, or the user dismissing
    // the native sheet). The platform throws NotAllowedError "No passkeys available". For a login probe
    // (registerIfMissing=false) that's not a hard failure — it means "no passkey resolves here": forget
    // the stale cache and report rejected so the caller falls through to the name/bootstrap path (the
    // person's own-subdomain ceremony) instead of dead-ending on the error. A register flow still throws.
    const noCredential = e instanceof DOMException ? e.name === 'NotAllowedError' : /not allowed|no passkey|timed out/i.test(e instanceof Error ? e.message : String(e));
    if (!registerIfMissing && noCredential) { clearPasskey(); return { status: 'rejected', reason: 'stale passkey cache' }; }
    throw e;
  }
  const r = await fetch('/connect/passkey', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      credentialIdDigest: passkey.credentialIdDigest,
      pubKeyX: passkey.pubKeyX.toString(),
      pubKeyY: passkey.pubKeyY.toString(),
      challenge,
      signature,
      aud: AUD,
    }),
  });
  const body = (await r.json()) as { status: string; token?: string };
  if (body.status === 'issued' && body.token) return { status: 'issued', token: body.token, passkey };
  if (body.status === 'bootstrap') return { status: 'bootstrap', passkey };
  return { status: (body.status as 'disambiguate' | 'rejected') ?? 'rejected', passkey };
}

// ── Deploy + claim in ONE userOp (ERC-4337 initCode + callData) ─────
// One signature instead of deploy-then-claim. The freshly-deployed account executes the name
// claim (register + set-primary) in the same op. Needs the SA address up front (the claim's
// newOwner) — derived deterministically from the passkey + salt (a factory view, no signature).

/** Deterministic passkey-direct SA address (mode 0, no custodians, the passkey, given salt). */
/** SHA-256 of the passkey RP id as a 32-byte hex string. This value is TWO things at once and both
 *  demand it equal `sha256(passkeyRpId())`:
 *
 *  1. CREATE2 salt input. The on-chain factory mixes `rpIdHash` into the passkey-direct SA salt, so
 *     predicting the SA address client-side MUST use the SAME value the deploy userOp uses. The client
 *     passes this on every prediction AND every deploy/register POST body so both computations agree and
 *     the registered address is the deployed address (orphan-registry root cause, live-debug 2026-06-01).
 *
 *  2. The SA's STORED rpIdHash. The account persists it and, on every passkey assertion, the verifier
 *     pins `authenticatorData.rpIdHash == stored` (WebAuthnLib `_checkAuthData`). The authenticator sets
 *     that assertion field to `sha256(rp.id)` where `rp.id = passkeyRpId()` (the home SUBDOMAIN —
 *     spec 229 P5 subdomain isolation). So this MUST hash `passkeyRpId()` and the ceremony MUST run on
 *     the home's own origin: signing from a different host changes the RP and fails verification
 *     (that mismatch, in the brief 2026-07-16 pin-to-parent detour, rejected every signature).
 *
 *  `passkeyRpId()` already carries the SSR/localhost/whitelabel fallbacks, so hashing it is correct on
 *  every host. (No fallback — ADR-0013 single mechanism: one consistent value end-to-end.) */
export async function derivePasskeyRpIdHash(): Promise<Hex> {
  const rpId = passkeyRpId();
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(rpId));
  const arr = Array.from(new Uint8Array(buf));
  return ('0x' + arr.map((b) => b.toString(16).padStart(2, '0')).join('')) as Hex;
}

/** On-chain `isCustodian` read — may THIS address sign for `sa`? Used to say, before a click, that an on-chain
 *  step needs the agent's custodian rather than failing with AA24 after it (spec 347 §9 separation of duties). */
export async function isCustodianOf(sa: Address, candidate: Address): Promise<boolean> {
  try { return await agentAccountClient().isCustodian(sa, candidate); } catch { return false; }
}

function agentAccountClient(): AgentAccountClient {
  return new AgentAccountClient({
    rpcUrl: DEFAULT_RPC_URL,
    chainId: CHAIN_ID,
    entryPoint: CONTRACTS.entryPoint,
    factory: CONTRACTS.agentAccountFactory,
  });
}

// ── Connected credential resolver (Registry "you" / Register gating) ──
//
// The custody CHECK itself is answered MCP-side over the knowledge base (ADR-0040, see
// `src/lib/registry.ts` → discovery agent `/custody`). The home only resolves the viewer's OWN on-chain
// custody identifier — the value it presents for itself. passkey/wallet resolve from local state; a
// Google/social member is custodied by their per-(iss,sub) KMS C_sub (derived server-side), so we ask
// demo-a2a for it with the custody session (`resolveCredential`, async). Their agents are all custodied by
// that one C_sub, so the same value matches every agent they steward.
export type ConnectedCredential = { kind: 'passkey'; digest: Hex } | { kind: 'eoa'; address: Address };

const isSocialVia = (via: string | undefined) => { const v = (via ?? '').toLowerCase(); return v === 'google' || v === 'youversion'; };

/** Sync, local-only resolution (passkey/wallet). Returns null for social (use `resolveCredential`).
 *  Robust to an AMBIGUOUS session `via`: a restored cross-subdomain SSO session carries via='sso' (or a
 *  cookie via), not 'passkey'/'wallet', so we don't branch solely on it — we use whatever local credential
 *  exists. For the read-only custody CHECK the passkey `credentialIdDigest` is the only thing needed
 *  (pubKeyX is NOT required — a sign-in assertion caches the digest even when the pubkey isn't re-derived). */
export function connectedCredential(via: string | undefined, name: string | null): ConnectedCredential | null {
  const v = (via ?? '').toLowerCase();
  const eoa = name ? recallHomeEoa(name) : undefined;
  // Wallet session → the remembered custodian EOA for this name.
  if (v === 'wallet') return eoa ? { kind: 'eoa', address: eoa } : null;
  // Passkey (or any restored/ambiguous session that has a local passkey) → its credentialIdDigest.
  const pk = loadPasskey();
  if (pk?.credentialIdDigest) return { kind: 'passkey', digest: pk.credentialIdDigest };
  // Last resort for an ambiguous session with a remembered wallet but no local passkey.
  if (eoa) return { kind: 'eoa', address: eoa };
  return null;
}

/** Ask demo-a2a for the connected Google/social member's KMS custodian C_sub (a public on-chain address;
 *  derived, not signed). Custody-session authenticated, CSRF — mirrors googleSignHash. */
export async function resolveGoogleCustodian(sessionToken: string): Promise<Address | null> {
  await ensureCsrfToken();
  const res = await custodyFetch('/a2a/custody/oidc/custodian', {
    method: 'POST',
    credentials: 'include',
    headers: { 'content-type': 'application/json', ...csrfHeaders() },
    body: JSON.stringify({ session: sessionToken }),
  });
  const b = (await res.json().catch(() => ({}))) as { ok?: boolean; custodian?: Address };
  return res.ok && b.ok && b.custodian ? b.custodian : null;
}

// ─── spec 321 W0 — connection-custodian cache (credential mirror for child agents) ────────────────
// A KMS/social home's C_sub is only derivable while a CUSTODY session is live (demo-a2a gates the
// derive on it), but the credential-mirror at org create must also work from a passkey session on the
// same home (the org would otherwise be passkey-only and unstewaradable from phone/email sessions —
// the 2026-07-10 sender_mismatch). So each custody session caches its C_sub per person (a PUBLIC
// on-chain address — same locality as loadPasskey), and org create reads the cache.
const CSUB_KEY = (person: Address): string => `ap-csub:${person.toLowerCase()}`;

/** Best-effort: derive + cache the session's KMS custodian (no-op for wallet/passkey sessions). */
export async function cacheConnectionCustodian(person: Address, via: string, token: string): Promise<void> {
  const v = (via ?? '').toLowerCase();
  if (!['google', 'youversion', 'email', 'phone'].includes(v)) return;
  try {
    const cSub = await resolveGoogleCustodian(token);
    if (cSub) localStorage.setItem(CSUB_KEY(person), cSub);
  } catch { /* cache is an optimization — the KMS org path still custodies by C_sub directly */ }
}

/** The cached KMS custodian for this person on this browser, if a custody session ever ran here. */
export function cachedConnectionCustodian(person: Address): Address | null {
  try {
    const v = localStorage.getItem(CSUB_KEY(person));
    return v && /^0x[0-9a-fA-F]{40}$/.test(v) ? (v as Address) : null;
  } catch { return null; }
}

/** Full resolution incl. social: passkey/wallet locally, Google/YouVersion via C_sub (needs the session
 *  token). Returns null when the viewer credential can't be determined (then the chain still gates). */
export async function resolveCredential(via: string | undefined, name: string | null, token?: string | null): Promise<ConnectedCredential | null> {
  if (isSocialVia(via)) {
    if (!token) return null;
    const cSub = await resolveGoogleCustodian(token).catch(() => null);
    return cSub ? { kind: 'eoa', address: cSub } : null;
  }
  return connectedCredential(via, name);
}

/** Can we pre-check custody for this session? (true → gate Register by ownership; false → leave it open.) */
export function canCheckCustody(via: string | undefined, name: string | null, token?: string | null): boolean {
  return isSocialVia(via) ? !!token : !!connectedCredential(via, name);
}

export async function derivePasskeySa(passkey: DemoPasskey, salt: bigint): Promise<Address> {
  const rpIdHash = await derivePasskeyRpIdHash();
  return agentAccountClient().getAddressForAgentAccount({
    custodians: [],
    passkey: {
      credentialIdDigest: passkey.credentialIdDigest,
      x: passkey.pubKeyX,
      y: passkey.pubKeyY,
      rpIdHash,
    },
    salt,
  });
}

/** EOA/SIWE-custodied SA address — MUST mirror the server's `/session/deploy` EOA spec
 *  (`custodians: [owner], salt`, mode 0, no passkey) so the predicted address == the
 *  deployed address (else the name-claim `newOwner` orphans). */
export async function deriveEoaSa(owner: Address, salt: bigint): Promise<Address> {
  return agentAccountClient().getAddressForAgentAccount({ custodians: [owner], salt });
}

/** Client-side "is this SA already deployed on-chain?" — a single `getBytecode` read via the a2a RPC proxy.
 *  Lets wallet signup detect fresh-vs-existing WITHOUT spending a SIWE (the old `siweLogin`-to-detect). On an
 *  RPC hiccup we return false (treat as fresh) — a redundant deploy of an existing SA fails server-side with a
 *  surfaced error, never a silent weaker path (ADR-0013). Deployed ⟺ this EOA custodies it (the address is
 *  derived from custodians=[EOA], so only a deploy under this EOA yields it). */
export async function isAgentDeployed(sa: Address): Promise<boolean> {
  try {
    const pub = createPublicClient({ chain: CHAIN, transport: http('/a2a/rpc') });
    const code = await pub.getBytecode({ address: sa });
    return !!code && code !== '0x';
  } catch {
    return false;
  }
}

/** Pick a free name + build the `executeBatch(register, setPrimary)` calldata the new SA runs
 *  to claim it (newOwner = the SA itself). Returned to ride along in the deploy userOp. */
type NameClaimRecords = {
  agentKind?: keyof typeof AGENT_KIND_ID;
  displayName?: string;
  appContext?: string;
  orgRole?: string;
  serviceUrl?: string;
  siteUrl?: string;
  description?: string;
};
const NAME_RECORD_STRING_PREDICATE: Record<Exclude<keyof NameClaimRecords, 'agentKind'>, Hex> = {
  displayName: PREDICATE_ID.displayName,
  appContext: keccak256(toBytes('atl:appContext')),
  orgRole: keccak256(toBytes('atl:orgRole')),
  serviceUrl: keccak256(toBytes('atl:serviceUrl')),
  siteUrl: keccak256(toBytes('atl:siteUrl')),
  description: keccak256(toBytes('atl:description')),
};

function buildNameRecordCalls(node: Hex, sa: Address, records: NameClaimRecords): ContractCall[] {
  const calls: ContractCall[] = [
    buildSetAddressAttributeCall({ resolver: CONTRACTS.agentNameResolver, node, predicate: PREDICATE_ID.addr, value: sa }),
  ];
  if (records.agentKind) {
    calls.push(buildSetBytes32AttributeCall({
      resolver: CONTRACTS.agentNameResolver,
      node,
      predicate: PREDICATE_ID.agentKind,
      value: AGENT_KIND_ID[records.agentKind],
    }));
  }
  for (const key of ['displayName', 'appContext', 'orgRole', 'serviceUrl', 'siteUrl', 'description'] as const) {
    const value = records[key];
    if (value) {
      calls.push(buildSetStringAttributeCall({ resolver: CONTRACTS.agentNameResolver, node, predicate: NAME_RECORD_STRING_PREDICATE[key], value }));
    }
  }
  return calls;
}

function childDiscoveryRecords(base: string, cOpts: CreateChildOpts): NameClaimRecords {
  const purpose = (cOpts.purpose ?? '').toLowerCase();
  const requestedBy = (cOpts.requestedBy ?? '').toLowerCase();
  const name = `${base.replace(/\.(impact|demo\.agent)$/i, '')}.impact`;
  const records: NameClaimRecords = { agentKind: 'org', displayName: name };
  if (purpose.includes('uupg') || requestedBy === 'uupg-tracker') {
    const orgRole = purpose.includes('alliance') ? 'alliance' : 'organization';
    records.appContext = 'uupg';
    records.orgRole = orgRole;
    records.serviceUrl = 'https://uupg.richardpedersen3.workers.dev/';
    if (orgRole === 'organization') records.siteUrl = `https://${name.replace(/\.impact$/i, '')}.impact-agent.me/`;
    records.description = orgRole === 'alliance'
      ? 'UUPG alliance agent discoverable by public Agent Naming metadata.'
      : 'UUPG organization agent discoverable by public Agent Naming metadata.';
  }
  return records;
}

async function buildClaimCallData(
  base: string,
  sa: Address,
  onStep?: (s: string) => void,
  exact = false,
  records: NameClaimRecords = { agentKind: 'person' },
  typed: TypedClaimOpts = {},
): Promise<{ ok: true; callData: Hex; calls: ContractCall[]; name: string } | { ok: false; error: string }> {
  const sub = subregistryForTld(typed.tld);
  if (!sub.ok) return { ok: false, error: sub.error };
  // exact (spec 275 MAM-D4): the member typed the precise label — claim it or fail, no
  // suffix bump. Otherwise forced-unique (spec 220) picks the next free `<base>[N]`.
  const tldQ = typed.tld ? `&tld=${encodeURIComponent(typed.tld)}` : '';
  const query = exact
    ? `/connect/name?exact=1&label=${encodeURIComponent(base)}${tldQ}`
    : `/connect/name?base=${encodeURIComponent(base)}${tldQ}`;
  onStep?.(exact ? 'Checking that name…' : 'Finding a free name…');
  const picked = (await (await fetch(query)).json()) as {
    label?: string;
    name?: string;
    node?: Hex;
    error?: string;
    taken?: boolean;
  };
  if (!picked.name || !picked.node || !picked.label) {
    if (picked.taken) return { ok: false, error: `“${base}.${typed.tld ?? AGENT_NAME_PARENT}” is already taken — pick another name.` };
    return { ok: false, error: picked.error ?? 'no free name' };
  }
  const register = buildSubregistryRegisterCall({ subregistry: sub.subregistry, label: picked.label, newOwner: sa });
  const setPrimary = buildSetPrimaryNameCall({ registry: CONTRACTS.agentNameRegistry, node: picked.node });
  // Typed claim (spec 346 §3.6): declare the derived type on the SA's profile FIRST; the name record's
  // agentKind is the ROOT of that type; the display name carries the typed suffix.
  const declare = sub.typed ? await declareTypeCalls(sa, typed.tld!, typed.serviceRole) : [];
  const effective: NameClaimRecords = sub.typed
    ? { ...records, agentKind: rootClassForDerivedType(derivedTypeForTld(typed.tld as never)), ...(records.displayName ? { displayName: `${picked.label}.${typed.tld}` } : {}) }
    : records;
  // `calls` is surfaced so an org-create can EXTEND the batch with approveHash(digest) calls
  // (spec 253) and still deploy + claim + approve in ONE userOp. `callData` is the standalone
  // deploy+claim batch for the simpler person-SA bootstrap callers.
  const calls: ContractCall[] = [...declare, register, setPrimary, ...buildNameRecordCalls(picked.node, sa, effective)];
  return { ok: true, callData: buildExecuteBatchCallData(calls), calls, name: picked.name };
}

/** spec 253 — `ContractCall` for `ApprovedHashRegistry.approveHash(key)`. Batched into the delegator's
 *  DEPLOY userOp so a counterfactual org/person pre-approves its outbound grants' digests; each grant then
 *  validates via the SA's ERC-1271 `0x03` approved-hash branch. R917-C-2 (spec 408 §1.2): what is approved
 *  is the EPOCH-BOUND key — a counterfactual account is at custody epoch 0, which is the only epoch this
 *  deploy-time builder may assume. A DEPLOYED account approves through `approveGrantHashes`, which reads
 *  its current epoch first. */
function buildApproveHashCall(digest: Hex, account: Address): ContractCall {
  // Spec 410 §1 (generation 3): a self-call on the account being deployed — it derives the key on chain.
  const scheme = CONTRACTS_GENERATION === 1 ? { generation: 1 as const } : CONTRACTS_GENERATION === 3 ? { generation: 3 as const, account } : { generation: 2 as const, epoch: 0n };
  return buildApproveHashKeyCall(CONTRACTS.approvedHashRegistry, digest, scheme);
}

/** B4 — pre-approve a set of the DELEGATOR's own grant digests in ONE userOp on the delegator SA: batch an
 *  `approveHash(digest)` call per digest into a single `executeBatch`, signed ONCE. Approved-hash (`0x03`)
 *  delegations then validate via the SA's ERC-1271 `0x03` branch. Lets `givePermission` fold the person-SA
 *  site + session grant approvals into one wallet prompt instead of an off-chain signature per leaf. The
 *  delegator SA MUST be deployed (it is — this is the member's home). No-op for an empty digest set. */
export async function approveGrantHashes(
  delegator: Address,
  signHash: SignHash,
  digests: Hex[],
): Promise<{ ok: true } | { ok: false; error: string }> {
  if (digests.length === 0) return { ok: true };
  // R917-C-2: a deployed account approves under its CURRENT custody epoch (0 if it has no code yet).
  const pc = createPublicClient({ chain: CHAIN, transport: http(DEFAULT_RPC_URL) });
  const scheme = await readApprovalScheme(pc, delegator, CONTRACTS_GENERATION);
  const callData = buildExecuteBatchCallData(digests.map((d) => buildApproveHashKeyCall(CONTRACTS.approvedHashRegistry, d, scheme)));
  const res = await executeCall(delegator, signHash, callData);
  return res.ok ? { ok: true } : { ok: false, error: res.error };
}

/** Bootstrap a passkey-direct person SA (no server custodian ever, P0-A). When `callData` is
 *  given, the deploy userOp ALSO executes it (e.g. claim the name) — one signature, not two. */
export async function bootstrapWithPasskey(
  passkey: DemoPasskey,
  onStep?: (s: string) => void,
  callData?: Hex,
): Promise<{ ok: true; agent: Address } | { ok: false; error: string }> {
  await ensureCsrfToken();
  onStep?.('Preparing your workspace…');
  // `rpIdHash` MUST match the value used in `derivePasskeySa` (sha256(passkeyRpId())).
  // The server's `/session/deploy` accepts an explicit `rpIdHash`; passing it
  // here removes the server's Origin-based fallback path so both sides use the
  // same value end-to-end (closes the orphan-registry root cause 2026-06-01).
  const rpIdHash = await derivePasskeyRpIdHash();
  const buildRes = await fetch('/a2a/session/deploy', {
    method: 'POST',
    credentials: 'include',
    headers: { 'content-type': 'application/json', ...csrfHeaders() },
    body: JSON.stringify({
      initMethod: 'passkey',
      credentialIdDigest: passkey.credentialIdDigest,
      pubKeyX: passkey.pubKeyX.toString(),
      pubKeyY: passkey.pubKeyY.toString(),
      rpIdHash,
      ...(callData ? { callData } : {}),
    }),
  });
  if (buildRes.status === 409) return { ok: false, error: 'Gas sponsorship is not enabled on the backend (paymaster).' };
  const built = (await buildRes.json().catch(() => ({}))) as { ok?: boolean; userOpHash?: Hex; userOp?: Record<string, unknown>; error?: string };
  if (!buildRes.ok || !built.ok || !built.userOpHash || !built.userOp) {
    return { ok: false, error: built.error ?? `deploy build failed (HTTP ${buildRes.status})` };
  }
  onStep?.('Confirm with your device…');
  // `justCreated`: this sign runs moments after registerPasskey — arm the Windows Hello
  // indexing-race handling (patient retries + guided failure) in signAssertion.
  const signature = await signWithPasskey(built.userOpHash, { justCreated: true, onRetry: onStep });
  onStep?.('Securing on the network…');
  const submitRes = await fetch('/a2a/session/deploy/submit', {
    method: 'POST',
    credentials: 'include',
    headers: { 'content-type': 'application/json', ...csrfHeaders() },
    body: JSON.stringify({ userOp: { ...built.userOp, signature } }),
  });
  const submitted = (await submitRes.json().catch(() => ({}))) as {
    ok?: boolean;
    deployedAddress?: Address;
    error?: string;
    detail?: string;
  };
  if (!submitRes.ok || !submitted.ok || !submitted.deployedAddress) {
    return {
      ok: false,
      error: [submitted.error, submitted.detail].filter(Boolean).join(' — ') || `deploy submit failed (HTTP ${submitRes.status})`,
    };
  }
  const agent = submitted.deployedAddress;
  // No separate enroll step: /connect/passkey derives the SA + records the facet on
  // the reconnect (with a post-deploy poll for RPC lag), so this is just the deploy.
  return { ok: true, agent };
}

// ── A2A service agent + relationship edge (spec 227 §6 / M5) ────────

/** Deploy a Smart Agent via demo-a2a (no facet enroll). Used for the A2A agent. */
async function deployAgent(
  deployBody: Record<string, unknown>,
  signHash: SignHash,
): Promise<{ ok: true; agent: Address } | { ok: false; error: string }> {
  await ensureCsrfToken();
  const buildRes = await fetch('/a2a/session/deploy', {
    method: 'POST',
    credentials: 'include',
    headers: { 'content-type': 'application/json', ...csrfHeaders() },
    body: JSON.stringify(deployBody),
  });
  if (buildRes.status === 409) return { ok: false, error: 'paymaster not enabled' };
  const built = (await buildRes.json().catch(() => ({}))) as { ok?: boolean; userOpHash?: Hex; userOp?: Record<string, unknown>; error?: string };
  if (!buildRes.ok || !built.ok || !built.userOpHash || !built.userOp) {
    return { ok: false, error: built.error ?? `deploy build failed (HTTP ${buildRes.status})` };
  }
  const signature = await signHash(built.userOpHash);
  const submitRes = await fetch('/a2a/session/deploy/submit', {
    method: 'POST',
    credentials: 'include',
    headers: { 'content-type': 'application/json', ...csrfHeaders() },
    body: JSON.stringify({ userOp: { ...built.userOp, signature } }),
  });
  const submitted = (await submitRes.json().catch(() => ({}))) as {
    ok?: boolean;
    deployedAddress?: Address;
    error?: string;
    detail?: string;
  };
  if (!submitRes.ok || !submitted.ok || !submitted.deployedAddress) {
    return {
      ok: false,
      error: [submitted.error, submitted.detail].filter(Boolean).join(' — ') || `deploy submit failed (HTTP ${submitRes.status})`,
    };
  }
  return { ok: true, agent: submitted.deployedAddress };
}

export interface ProvisionResult {
  a2aAgent: Address;
  edgeId: Hex;
}

/** Provision a 2nd SA (the A2A service agent) custodied by the same credential, and
 *  link `a2a --OPERATES_ON_BEHALF_OF--> person` (a2a proposes as subject; person
 *  confirms as object — architect F1). Both txs signed by the user's one credential. */
export async function provisionA2aAgent(
  via: 'wallet' | 'passkey',
  personAgent: Address,
  onStep?: (s: string) => void,
): Promise<{ ok: true; result: ProvisionResult } | { ok: false; error: string }> {
  const A2A_SALT = '1'; // distinct from the person SA (salt 0) -> distinct address
  let signHash: SignHash;
  let deployBody: Record<string, unknown>;
  if (via === 'wallet') {
    const addr = await connectWallet();
    signHash = (h) => personalSign(addr, h);
    deployBody = { initMethod: 'eoa', owner: addr, salt: A2A_SALT };
  } else {
    const pk = loadPasskey();
    if (!pk) return { ok: false, error: 'no passkey on this device' };
    signHash = passkeySignHash;
    deployBody = {
      initMethod: 'passkey',
      credentialIdDigest: pk.credentialIdDigest,
      pubKeyX: pk.pubKeyX.toString(),
      pubKeyY: pk.pubKeyY.toString(),
      salt: A2A_SALT,
    };
  }

  onStep?.('Deploying your agent service…');
  const dep = await deployAgent(deployBody, signHash);
  if (!dep.ok) return { ok: false, error: `agent deploy failed: ${dep.error}` };
  const a2aAgent = dep.agent;
  if (a2aAgent.toLowerCase() === personAgent.toLowerCase()) {
    return { ok: false, error: 'agent service collided with the person agent (salt)' };
  }

  const relationships = CONTRACTS.agentRelationship;
  const relationshipType = RELATIONSHIP_TYPE.OPERATES_ON_BEHALF_OF as RelationshipType;

  onStep?.('Linking it to operate on your behalf…');
  const propose = buildProposeEdgeCall({ relationships, subject: a2aAgent, object: personAgent, relationshipType });
  // a2a = subject (proposer); freshly deployed (nonce 0 consumed) → first op is nonce 1.
  const p = await executeCall(a2aAgent, signHash, buildExecuteCallData(propose), { minNonce: 1n, attempts: 10 });
  if (!p.ok) return { ok: false, error: `propose edge failed: ${p.error}` };

  onStep?.('Confirming the link…');
  const edgeId = computeEdgeId(a2aAgent, personAgent, relationshipType);
  const confirm = buildConfirmEdgeCall({ relationships, edgeId });
  await executeCall(personAgent, signHash, buildExecuteCallData(confirm), { attempts: 4 }); // person = object (confirmer); best-effort

  return { ok: true, result: { a2aAgent, edgeId } };
}

// ── Create a child agent custodied by the ROOT passkey, on behalf of a relying site ──
//
// The template for ALL agents a relying site asks the central auth to create (organization
// now; Treasury / any service agent later — memory project_demo_org_durable_org_custody).
// Every such agent follows the SAME pattern as the person SA: deployed here, custodied by
// the person's ROOT passkey ONLY (never the relying site's per-origin key, never the person
// SA — the latter is contract-forbidden as a custodian). The relying site is handed back a
// scoped, redeemer-bound delegation (child → the site's delegate SA) so it can operate the
// child without another passkey ceremony (ADR-0019).

export interface CreatedAgent {
  childAgent: Address;
  childName: string;
  edgeId: Hex;
  governed: boolean;
  delegation: DelegationWire; // child → relying site's delegate SA (scoped)
  /** ADR-0025: the person SA + the private related-agent credential (self-issued,
   *  unsigned for the demo — the proofHash anchors integrity; the vault store at
   *  the person's home during the authenticated ceremony provides provenance). */
  person: Address;
  purpose: string;
  requestedBy: string;
  credential: unknown;
  proofHash: Hex;
  /** Optional org → broker-org delegation (so a broker can later list its orgs). */
  brokerDelegation?: DelegationWire;
  /** A best-effort write still in flight from the org (its public naming records): awaited before the ceremony
   *  returns, never on the critical path of the setup that follows the deploy (2026-10-22). */
  pendingWrites?: Promise<void>;
  /** The org → app-service-agent Operational Intent grant, when the app declares a service SA. */
  operationalDelegation?: DelegationWire;
  /** The org → app-workspace READ grant (whitelabel `org_read_grant`), when the app declares one. */
  readGrantDelegation?: DelegationWire;
  /** spec 246 — person↔org scoped read delegations, both signed by the ROOT (custodian
   *  of BOTH SAs). membership = person→org (the created ORG can read the MEMBER person's
   *  data); stewardship = org→person (the PERSON can read / oversee the org's data).
   *  Best-effort: each is a separate signing ceremony, so a cancelled prompt leaves them
   *  undefined rather than orphaning the (already-deployed) org — see createChildAgentForSite. */
  membershipDelegation?: DelegationWire;
  stewardshipDelegation?: DelegationWire;
}

export interface CreateChildOpts {
  /** App-level purpose tag, e.g. `jp-adopter-org` (free string — ADR-0021). */
  purpose?: string;
  /** The relying app's OIDC client_id (who requested the link). */
  requestedBy?: string;
  /** A broker org SA to also grant scoped read access to (org → broker delegation). */
  grantOrg?: Address;
  /** Home session, for the demo-custody wallet branch (keys live at the Home, not the browser). */
  sessionToken?: string;
}

/** Deploy a child SA (org / service agent) custodied by the ROOT passkey, claim `<base>.demo.agent`,
 *  record `person --relationshipType--> child` (person proposes, child confirms — both signed by
 *  the ROOT passkey, the person's & child's custodian), and mint the scoped child→site delegation.
 *  `relationshipType` defaults to HAS_GOVERNANCE_OVER (organization). */
export async function createChildAgentForSite(
  personAgent: Address,
  base: string,
  delegateSA: Address,
  onStep?: (s: string) => void,
  relationshipType: RelationshipType = RELATIONSHIP_TYPE.HAS_GOVERNANCE_OVER as RelationshipType,
  cOpts: CreateChildOpts = {},
  via: string = 'passkey',
): Promise<{ ok: true; result: CreatedAgent } | { ok: false; error: string }> {
  // Name-independent salt (ADR-0010): credential scope + entropy, never the name.
  const saltBytes = crypto.getRandomValues(new Uint8Array(8));
  let salt = 0n;
  for (const b of saltBytes) salt = (salt << 8n) | BigInt(b);

  // Resolve the credential rail (the SAME credential that custodies the person SA, MAM-D2): derive the
  // child SA, choose the signer, build the matching deploy body. WALLET signs via the EOA (personalSign,
  // initMethod 'eoa'); passkey signs on-device. Google/KMS members go through createOrganizationWithGoogle
  // (createOrganization routes KMS there), never here. Derive the SA up front so deploy + claim its name land
  // in ONE userOp (one prompt). Mirrors createManagedAgent's all-custody branch.
  let childAgent: Address;
  let signHash: SignHash;
  let deployBody: Record<string, unknown>;
  if (via === 'wallet') {
    // DEMO ACCOUNTS FIRST — the same branch createManagedAgent grew for workspace deploys: a demo
    // person's custodian key lives AT THE HOME, and connectWallet() here surfaced as "No Ethereum
    // wallet found" (or signed as the wrong person) on every org/team create.
    const demoOwner =
      cOpts.sessionToken && (await isDemoCustodyHome(cOpts.sessionToken))
        ? await demoCustodianFor(personAgent)
        : null;
    const owner = demoOwner ?? (await connectWallet());
    childAgent = await deriveEoaSa(owner, salt);
    signHash = demoOwner && cOpts.sessionToken ? demoCustodySignHash(cOpts.sessionToken) : (h) => personalSign(owner, h);
    deployBody = { initMethod: 'eoa', owner, salt: salt.toString() };
  } else {
    const pk = loadPasskey();
    if (!pk) return { ok: false, error: 'Your central-auth passkey isn’t on this device — sign in to Agentic Connect first.' };
    childAgent = await derivePasskeySa(pk, salt);
    signHash = passkeySignHash;
    // rpIdHash MUST match derivePasskeySa (sha256(passkeyRpId())) — passed explicitly so the server doesn't fall
    // back to Origin derivation (orphan-registry root cause, live-debug 2026-06-01).
    const rpIdHash = await derivePasskeyRpIdHash();
    deployBody = {
      initMethod: 'passkey',
      credentialIdDigest: pk.credentialIdDigest,
      pubKeyX: pk.pubKeyX.toString(),
      pubKeyY: pk.pubKeyY.toString(),
      rpIdHash,
      salt: salt.toString(),
    };
  }
  if (childAgent.toLowerCase() === personAgent.toLowerCase()) {
    return { ok: false, error: 'agent collided with your person agent (salt)' };
  }
  const claim = await buildClaimCallData(base, childAgent, onStep, false, childDiscoveryRecords(base, cOpts), typedTldForKind('org') ?? {});
  if (!claim.ok) return { ok: false, error: claim.error };

  // spec 253 — ONE PROMPT. The org's outbound grants are built as approved-hash (0x03
  // sentinel) delegations BEFORE deploy; each grant's approveHash(digest) is batched into
  // the org's deploy userOp. The org (childAgent) is the delegator of all three, so it can
  // pre-approve their digests under its own address in the SAME op it deploys — no per-grant
  // passkey. Build each delegation ONCE and reuse the exact struct on the wire, so the digest
  // approved on-chain == the digest the relayer + redeem recompute (no salt re-randomization).
  //   • site grant:  child → relying site's delegate SA
  //   • broker grant: child → grantOrg (optional)
  //   • stewardship: child → person (the person can read / oversee the org's data)
  // MEMBERSHIP (person → org) is the one grant the org CAN'T approve (its delegator is the
  // PERSON SA), so it is DEFERRED — re-minted later from the person's home or on first need.
  const siteGrant = buildApprovedSiteDelegation(childAgent, delegateSA);
  const approveCalls: ContractCall[] = [buildApproveHashCall(siteGrant.digest, childAgent)];

  let brokerGrant: ReturnType<typeof buildApprovedSiteDelegation> | undefined;
  if (cOpts.grantOrg && cOpts.grantOrg.toLowerCase() !== delegateSA.toLowerCase()) {
    brokerGrant = buildApprovedSiteDelegation(childAgent, cOpts.grantOrg);
    approveCalls.push(buildApproveHashCall(brokerGrant.digest, childAgent));
  }
  const stewardship = buildApprovedSiteDelegation(childAgent, personAgent);
  approveCalls.push(buildApproveHashCall(stewardship.digest, childAgent));

  // The OPERATIONAL INTENT grant (org → the app's service agent), folded into the same batch so it
  // costs no extra signature. Minted ONLY when the relying app declares a dedicated service SA:
  // absent one there is nobody to grant to, and granting to the shared registry delegate would hand
  // operational authority to every app that names it. See skills' docs/operational-intent-grant.md.
  const operationalSA = getClient(cOpts.requestedBy ?? '')?.operational_delegate as Address | undefined;
  let operationalGrant: ReturnType<typeof buildApprovedOperationalIntentDelegation> | undefined;
  if (operationalSA && operationalSA.toLowerCase() !== delegateSA.toLowerCase()) {
    operationalGrant = buildApprovedOperationalIntentDelegation(childAgent, operationalSA);
    approveCalls.push(buildApproveHashCall(operationalGrant.digest, childAgent));
  }

  // The ORG READ grant (org → the app's workspace agent), same batch, same reasoning — and the same
  // refusal to grant to the shared registry delegate. See buildApprovedOrgReadDelegation.
  const orgReadCfg = getClient(cOpts.requestedBy ?? '')?.org_read_grant;
  let orgReadGrant: ReturnType<typeof buildApprovedOrgReadDelegation> | undefined;
  if (orgReadCfg && orgReadCfg.delegate.toLowerCase() !== delegateSA.toLowerCase()) {
    orgReadGrant = buildApprovedOrgReadDelegation(childAgent, orgReadCfg.delegate as Address, orgReadCfg);
    approveCalls.push(buildApproveHashCall(orgReadGrant.digest, childAgent));
  }

  // spec 321 W0 — credential mirror: the contract FORBIDS an SA as custodian (custody is
  // credential-shaped; agent→agent authority is delegation), so "the person stewards the org" must
  // hold at the CREDENTIAL level. The KMS org path already deploys C_sub-custodied orgs; this path
  // deploys passkey/EOA-custodied ones — ALSO install the person's cached KMS custodian (when their
  // home has one) so every session credential that controls the person can steward the org
  // (custodian-backs-all-authority). Batched into the same deploy userOp: `addCustodian` is
  // onlySelf and the fresh org has no custody module yet, so the self-call is ungated.
  const mirrorCSub = cachedConnectionCustodian(personAgent);
  const mirrorCalls: ContractCall[] = mirrorCSub
    ? [{ to: childAgent, value: 0n, data: encodeFunctionData({ abi: ADD_CUSTODIAN_ABI, functionName: 'addCustodian', args: [mirrorCSub] }) }]
    : [];

  // deploy + claim name + approve every org grant (+ credential mirror) — all in ONE atomic userOp.
  const deployCallData = buildExecuteBatchCallData([...claim.calls, ...approveCalls, ...mirrorCalls]);

  onStep?.('Deploying your organization — name + all access grants…');
  // deploy + claim + approve all grants — ONE signature, on the member's resolved credential rail (the
  // deployBody + signHash chosen above by `via`: eoa for wallet, passkey otherwise).
  const dep = await deployAgent({ ...deployBody, callData: deployCallData }, signHash);
  if (!dep.ok) return { ok: false, error: `agent deploy failed: ${dep.error}` };

  // spec 253 — the org's site / broker / stewardship grants are validated via the on-chain
  // approved hashes set INSIDE the deploy batch above (not an off-chain signature), so the org
  // SA must be deployed AND RPC-visible before the relying app exchanges its grant. The OP's
  // verifier does a single isDeployed check and returns "delegator not yet deployed (retry
  // shortly)" on a lagged read replica (SEC-011). The deploy is mined (the relayer confirmed the
  // receipt), but a replica can lag a few seconds — the per-grant passkey prompts used to mask
  // this, and one-prompt removed them. Poll briefly so the org is visible before the ceremony
  // hands the grant off. Bounded (ADR-0013): the SAME getCode call, capped at ~15s.
  onStep?.('Confirming your organization…');
  {
    const pub = createPublicClient({ chain: CHAIN, transport: http('/a2a/rpc') });
    for (let i = 0; i < 15; i++) {
      const code = await pub.getBytecode({ address: childAgent }).catch(() => undefined);
      if (code && code !== '0x') break;
      await new Promise((r) => setTimeout(r, fastPollMs(1000)));
    }
  }

  // ADR-0025: person↔org is a PRIVATE vault credential, NOT a public on-chain edge.
  // The control relationship is implicit in custody (the org is custodied by the
  // person's ROOT credential); we do NOT write any AgentRelationship edge. `edgeId`
  // stays as a deterministic local id for back-compat of the return shape only —
  // nothing is recorded on-chain. (The private situation credential + the vault
  // store live in the org-create grant path; see spec 246.)
  const edgeId = computeEdgeId(personAgent, childAgent, relationshipType);

  // child → relying site's delegate SA — authorized via the approved hash batched above
  // (rides the wire with the 0x03 sentinel, validated by the org SA's ERC-1271 branch).
  const delegation = siteGrant.delegation;

  // ADR-0025 / spec 246: the private, self-issued related-agent credential — the
  // person's own vault record of "I have this org, created for this app's flow".
  // Built unsigned (no extra device prompt); the proofHash anchors integrity and
  // the vault store happens at the home during this authenticated ceremony.
  const purpose = cOpts.purpose ?? 'related-org';
  const requestedBy = cOpts.requestedBy ?? '';
  const credential = buildRelatedAgentCredential({
    holder: personAgent,
    relatedAgent: childAgent,
    purpose,
    requestedBy,
    issuerCaip10: `eip155:${CHAIN_ID}:${personAgent}`,
    body: { agentName: claim.name },
    validFrom: new Date().toISOString(),
  });
  const proofHash = relatedAgentProofHash(credential);

  // org → broker-org scoped grant (spec 246 §5) + org → person stewardship — BOTH were
  // approved in the deploy batch above (org is the delegator of each), so they ride the wire
  // with the 0x03 sentinel; no extra prompts.
  const brokerDelegation: DelegationWire | undefined = brokerGrant ? toWire(brokerGrant.delegation) : undefined;
  const stewardshipDelegation: DelegationWire = toWire(stewardship.delegation);

  // spec 253 — MEMBERSHIP (person → org, so the org can read the MEMBER person's data) is
  // DEFERRED. Its delegator is the PERSON SA, which can't pre-approve inside the ORG's deploy
  // op; minting it now would cost a second passkey, defeating the one-prompt goal. The org is
  // fully functional without it (site + broker + stewardship grants are all live from the one
  // deploy op); membership is re-minted later from the person's home or on first need.
  const membershipDelegation: DelegationWire | undefined = undefined;

  requestReindex([childAgent]); // auto-index: the new org/child agent appears in discovery immediately
  return {
    ok: true,
    result: {
      childAgent, childName: claim.name, edgeId, governed: false,
      delegation: toWire(delegation),
      person: personAgent, purpose, requestedBy, credential, proofHash, brokerDelegation,
      membershipDelegation, stewardshipDelegation,
      // Approved in the deploy batch above; RETURNED because the ceremony is the only moment either
      // exists — the salt is random, so a body that isn't handed back can never be presented.
      operationalDelegation: operationalGrant ? toWire(operationalGrant.delegation) : undefined,
      readGrantDelegation: orgReadGrant ? toWire(orgReadGrant.delegation) : undefined,
    },
  };
}

// ── spec 275: multi-agent management from the Personal Trust Home ──────────────────
//
// The member, custodian of their Person SA, builds out the rest of their agent tree —
// a Person Treasury, Org(s), and each Org's Treasury — each an on-chain SA with an EXACT
// name, custodied by the SAME ROOT passkey, created in ONE gasless prompt. The links between
// them are PRIVATE vault credentials (ADR-0025), indexed under the person for the tree view.

// 'workspace' (ADR-0046) — an APP WORKSPACE agent: a service-class SA that holds an application's
// shared roster/state in its own vault (first user: Gather27's workspace of member organizations).
// It MIRRORS the treasury pattern rather than extending it — another service ROLE under the closed
// Person/Org/Service class set, never a subclass of treasury. Typically org-parented: the app's
// governing org custodies it and its custodian runs the service-agent-wire ceremony against the
// app's a2a Worker.
// spec 346 — the agents a person can charter from their home, each named by the typed suffix it claims.
// `service` is the GENERIC service agent (`.svc`): a workspace, treasury and registry are service-class
// too, but they carry a role the substrate knows about, and this one is the plain one (ADR-0046 — the
// class is the trichotomy, the role is a label).
//
// `person` — ANOTHER PERSON OF YOUR OWN. A custodian is not limited to one: somebody walks a long trail and
// is known on it as Summit, somebody writes under another name, somebody plays a part in a game for six
// evenings and wants what that character learned kept in its own vault rather than muddled into theirs.
// Each is a person-shaped agent of its own — its own `.me` name, its own card, its own vault, its own memory
// of the people it has met under that name — custodied by the same credential, and one of them is the
// DEFAULT its Home opens as (`ap:DefaultPersonChoice`; `lib/default-person.ts`).
//
// It is NOT a second root: the credential is the same, so nothing here is a new identity to recover, and the
// choice between them permits nothing. Moving to another of your people is a change of CONTEXT, not of
// power — every act still runs under a mandate signed for that request, by that agent.
export type AgentKind = 'person' | 'person-treasury' | 'org' | 'org-treasury' | 'workspace' | 'team' | 'circle' | 'church' | 'household' | 'service';

export interface ManagedAgent {
  agent: Address;
  name: string;
  kind: AgentKind;
  /** Parent in the tree: person SA for person-treasury/org; the ORG SA for org-treasury. */
  parent: Address;
  createdAt: number | null;
  proofHash?: string;
  /** spec 318: 'steward' = custodial control (default); 'member' = authority-only (channels +
   *  switcher visibility, never inbox/data/treasury control).
   *  'self' = ANOTHER PERSON OF THE SAME CUSTODIAN — neither stewarded nor a membership: it is them, under
   *  a different name. Distinguished because a steward oversees somebody else's agent and a member belongs
   *  to an organization, and this is neither; reading it as 'steward' would file your own trail name under
   *  things you look after. */
  relationship?: 'steward' | 'member' | 'self';
  /** App-level purpose tag written when the person↔org link was created (e.g. `commons:community`). */
  purpose?: string;
  /**
   * The org→person stewardship delegation, when this person stewards it (spec 341 §5.1c).
   *
   * Carried because an ORGANIZATION has no session of its own: acting as one means presenting this,
   * and an interface that can show the org in a switcher but cannot prove control over it produces
   * exactly the 403s nobody can diagnose. It is an authority artifact, not a secret — signed, scoped,
   * and revocable — and the endpoint already returns it.
   */
  stewardshipDelegation?: unknown;
  /** spec 342 — projected lifecycle status (absent = active). See `lib/org-lifecycle.ts`. */
  status?: OrgLifecycleStatus;
  /** spec 344/424 — for a governed `.workspace`, the ORGANIZATION that governs it (`aporg:governedBy`). A
   *  workspace is parented by the person, so this carries the org relationship the `parent` chain does not —
   *  the switcher reads it to show "workspace · you → <org>". Absent for an org, a standalone workspace, or a
   *  person-held service. */
  governor?: Address;
  /** The `name` is a PRIVATE/LOCAL name the viewer holds (from the owner's vault via member access, surfaced as a
   *  rebuildable `org-localname:<agent>` projection), not a publicly registered naming-service name. Surfaces have
   *  marked it so (a trailing `*`): the viewer can read it, but a stranger reading the chain could not. */
  nameIsLocal?: boolean;
}

export interface CreateManagedAgentResult {
  agent: Address;
  name: string;
  kind: AgentKind;
  parent: Address;
  /** The child→parent oversight grant (spec 246) — returned so create-time seeding (org:profile,
   *  spec 321 item-1) can write the child's vault without re-fetching the link. */
  stewardshipDelegation?: DelegationWire;
}

/** Public demo roster names the custodian EOA. Used only after isDemoCustodyHome. */
export async function demoCustodianFor(person: Address): Promise<Address | null> {
  try {
    const r = await fetch('/connect/demo-personas');
    const b = (await r.json()) as { personas?: Array<{ sa?: string; custodian?: string }> };
    const row = (b.personas ?? []).find((p) => (p.sa ?? '').toLowerCase() === person.toLowerCase());
    return row?.custodian && /^0x[0-9a-fA-F]{40}$/.test(row.custodian) ? (row.custodian as Address) : null;
  } catch {
    return null;
  }
}

/** Deploy + claim the EXACT name (MAM-D4) + pre-approve the parent stewardship grant — ALL in
 *  ONE gasless passkey userOp (MAM-D5) — then record the PRIVATE link under the person's home
 *  vault (MAM-D7). Custodied by the member's ROOT passkey (MAM-D2). Throws "name taken" rather
 *  than bumping a suffix (MAM-INV-2). */
export async function createManagedAgent(
  input: {
    kind: AgentKind; label?: string; parent: Address; person: Address; via: string;
    /**
     * WHO STEWARDS IT, when that is not the parent. The link's `parent` says whose the agent is (readable as
     * `ap:charteredUnder`); the stewardship wire says who may act for it — and for a GOVERNED WORKSPACE those
     * are two agents: the workspace hangs under the organization that governs it, while its custodian keeps
     * stewarding it, because the organization has no session of its own and every steward gate
     * (`verifyStewardship`, the field app's `act-as`) checks the wire against the PERSON. Defaults to the
     * parent, which is every other kind: a treasury is stewarded by whoever it hangs under.
     */
    steward?: Address;
  },
  sessionToken: string,
  onStep?: (s: string) => void,
): Promise<{ ok: true; result: CreateManagedAgentResult } | { ok: false; error: string }> {
  // Orgs MUST be named — name-deferral (nameless SA, name later) is for person
  // treasuries and org treasuries only. An org is a counterparty-facing identity.
  if (input.kind === 'org' && !(input.label && input.label.trim().length >= 3)) {
    return { ok: false, error: 'Organizations require a name — pick a label of at least 3 characters.' };
  }

  // KMS family (Google / YouVersion / email / phone — specs 235/319/320): the member is KMS-custodied
  // by C_sub, which (spec 235 §5.4) only signs for the SAs it custodies — built SERVER-SIDE. So the
  // whole deploy+name+grant runs on the worker (/custody/oidc/bootstrap-agent), zero device prompts,
  // and we just record the vault link. Case-insensitive + the WHOLE family (custodian-backs-all-
  // authority): the old exact 'Google'|'YouVersion' match dropped phone/email sessions into the
  // passkey branch — "Your passkey isn't on this device" for a member who connected by phone.
  const viaLc = input.via.toLowerCase();
  if (viaLc === 'google' || viaLc === 'youversion' || viaLc === 'email' || viaLc === 'phone') {
    return createManagedAgentSocial(input, sessionToken, onStep);
  }

  // Name-independent random salt (ADR-0010) → a distinct SA under the one root credential (MAM-INV-4).
  const saltBytes = crypto.getRandomValues(new Uint8Array(8));
  let salt = 0n;
  for (const b of saltBytes) salt = (salt << 8n) | BigInt(b);

  // Resolve the credential method (the SAME root credential that custodies the Person SA,
  // MAM-D2): derive the child SA, choose the signer, and build the matching deploy body.
  let child: Address;
  let signHash: SignHash;
  let deployBody: Record<string, unknown>;
  if (viaLc === 'wallet') {
    // Demo people (Ivan Petrov…) are wallet-credential homes whose EOA is held by
    // this Home, not by the browser. connectWallet() would open MetaMask as the wrong
    // person. Same zero-prompt path signHashFor already uses for grants.
    const demoOwner =
      sessionToken && (await isDemoCustodyHome(sessionToken))
        ? await demoCustodianFor(input.person)
        : null;
    const owner = demoOwner ?? (await connectWallet());
    child = await deriveEoaSa(owner, salt);
    signHash = demoOwner && sessionToken ? demoCustodySignHash(sessionToken) : (h) => personalSign(owner, h);
    deployBody = { initMethod: 'eoa', owner, salt: salt.toString() };
  } else {
    const pk = loadPasskey();
    if (!pk) return { ok: false, error: 'Your passkey isn’t on this device — sign in to your home first.' };
    child = await derivePasskeySa(pk, salt);
    signHash = passkeySignHash;
    const rpIdHash = await derivePasskeyRpIdHash(); // MUST match derivePasskeySa (sha256(passkeyRpId())).
    deployBody = {
      initMethod: 'passkey',
      credentialIdDigest: pk.credentialIdDigest,
      pubKeyX: pk.pubKeyX.toString(),
      pubKeyY: pk.pubKeyY.toString(),
      rpIdHash,
      salt: salt.toString(),
    };
  }
  if (child.toLowerCase() === input.person.toLowerCase() || child.toLowerCase() === input.parent.toLowerCase()) {
    return { ok: false, error: 'address collided with an existing agent (salt) — please retry' };
  }

  // Name is OPTIONAL (true name-deferral, cf. spec 257). If the member typed a label we claim it
  // EXACTLY (MAM-D4, no suffix); otherwise the agent deploys NAMELESS and can be named later
  // (nameManagedAgent). A nameless agent is fully functional — the SA address is the canonical id
  // (ADR-0010); the name is just an optional public facet.
  const wantName = !!input.label && input.label.trim().length >= 3;
  let claimCalls: ContractCall[] = [];
  let name = '';
  if (wantName) {
    const claim = await buildClaimCallData(input.label!, child, onStep, true, {
      // THE CLASS COMES FROM THE CLASSIFIER, not from a list kept by hand here. Both this and the naming
      // path used to enumerate the org kinds and send everything else as 'service', so a person would have
      // claimed a `.me` name declaring itself service-class — which the typed claim refuses outright
      // (spec 346 §3.6: the suffix, the on-chain type and the name record's class must agree).
      agentKind: agentClassOf(input.kind),
      displayName: `${input.label!.replace(/\.(impact|demo\.agent)$/i, '')}.${typedTldForKind(input.kind)?.tld ?? AGENT_NAME_PARENT}`,
    }, typedTldForKind(input.kind) ?? {});
    if (!claim.ok) return { ok: false, error: claim.error };
    claimCalls = claim.calls;
    name = claim.name;
  }

  // Stewardship grant child → its steward (the parent, unless the caller split the two — see `steward`) so
  // that SA can read/oversee this agent's vault (spec 246). The child is its own delegator, so it pre-approves
  // the digest (0x03 sentinel, spec 253) INSIDE the deploy batch — no second prompt.
  const stewardship = buildApprovedSiteDelegation(child, input.steward ?? input.parent);
  // spec 321 W0 credential mirror (same as createChildAgentForSite): also install the person's
  // cached KMS custodian so a phone/email session can steward this agent (never SA-as-custodian —
  // the contract forbids it; custody is credential-shaped).
  const mirrorCSub = cachedConnectionCustodian(input.person);
  const mirrorCalls: ContractCall[] = mirrorCSub
    ? [{ to: child, value: 0n, data: encodeFunctionData({ abi: ADD_CUSTODIAN_ABI, functionName: 'addCustodian', args: [mirrorCSub] }) }]
    : [];
  const deployCallData = buildExecuteBatchCallData([...claimCalls, buildApproveHashCall(stewardship.digest, child), ...mirrorCalls]);

  onStep?.(wantName ? 'Deploying your agent — name + access grant…' : 'Deploying your agent (unnamed)…');
  // deploy + claim exact name + approve stewardship — ONE signature from the root credential.
  const dep = await deployAgent({ ...deployBody, callData: deployCallData }, signHash);
  if (!dep.ok) return { ok: false, error: `agent deploy failed: ${dep.error}` };

  // MAM-INV-1 — the SA must be deployed AND RPC-visible before it counts as "created" (SEC-011).
  onStep?.('Confirming on the network…');
  {
    const pub = createPublicClient({ chain: CHAIN, transport: http('/a2a/rpc') });
    for (let i = 0; i < 15; i++) {
      const code = await pub.getBytecode({ address: child }).catch(() => undefined);
      if (code && code !== '0x') break;
      await new Promise((r) => setTimeout(r, fastPollMs(1000)));
    }
  }

  // ADR-0025: private, self-issued related-agent credential (unsigned — proofHash anchors integrity,
  // the authenticated home session provides provenance). Holder = the parent in the tree.
  const credential = buildRelatedAgentCredential({
    holder: input.parent,
    relatedAgent: child,
    purpose: input.kind,
    requestedBy: '',
    issuerCaip10: `eip155:${CHAIN_ID}:${input.person}`,
    body: { agentName: name },
    validFrom: new Date().toISOString(),
  });
  const proofHash = relatedAgentProofHash(credential);

  // MAM-D7 — persist into the person's home vault via the session-authorized POST. Indexed
  // under the person (root) so org-treasuries render in the tree even though their holder is the org.
  onStep?.('Saving to your private vault…');
  const save = await fetch('/connect/related-orgs', {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${sessionToken}` },
    body: JSON.stringify({
      person: input.person,
      orgAgent: child,
      orgName: name,
      purpose: input.kind,
      kind: input.kind,
      parent: input.parent,
      stewardshipDelegation: toWire(stewardship.delegation),
      proofHash,
    }),
  });
  invalidateRelatedOrgs(); // this write changed the person's agents — the shared read must not serve the old payload
  if (!save.ok) {
    const e = (await save.json().catch(() => ({}))) as { error?: string };
    return { ok: false, error: `agent deployed${name ? ` (${name})` : ''} but saving the link failed: ${e.error ?? save.status}` };
  }

  requestReindex([child]); // auto-index: the new managed agent (treasury/org) appears in discovery now
  // spec 321/246 — the creator is the org's FIRST MEMBER: mint their membership delegation now
  // ("deferred to first need" — this is it). Best-effort inside recordOrgMembership.
  if (input.kind === 'org' || input.kind === 'team' || input.kind === 'circle' || input.kind === 'church' || input.kind === 'household') {
    onStep?.('Adding you as the first member…');
    await recordOrgMembership(input.person, child, signHash, sessionToken);
    // Spec 410 §8 — the founder's own membership credential: both signatures are hers at creation. Best-effort.
    try { const f = await issueFounderCredential(input.person, child, signHash, sessionToken); if (!f.ok) console.warn('[org-create] the founder\'s membership credential was not issued:', f.error); }
    catch (e) { console.warn('[org-create] the founder\'s membership credential was not issued:', e); }
  }
  return { ok: true, result: { agent: child, name, kind: input.kind, parent: input.parent, stewardshipDelegation: toWire(stewardship.delegation) } };
}

/** spec 275 — claim an EXACT name for an already-deployed NAMELESS managed agent (name-later).
 *  Runs `executeBatch(register, setPrimary)` AS the agent via its root credential (one gasless
 *  prompt), then updates the private vault record's name (server MERGES, so delegations persist). */
export async function nameManagedAgent(
  input: { agent: Address; label: string; kind: AgentKind; parent: Address; person: Address; via: string },
  sessionToken: string,
  onStep?: (s: string) => void,
): Promise<{ ok: true; name: string } | { ok: false; error: string }> {
  // KMS family (Google / YouVersion / email / phone): the worker's C_sub signs register+setPrimary AS
  // the agent (server-side, zero device prompts). Case-insensitive, whole family — same fix as
  // createManagedAgent (the exact 'Google'|'YouVersion' match stranded phone/email sessions).
  const viaLc = input.via.toLowerCase();
  if (viaLc === 'google' || viaLc === 'youversion' || viaLc === 'email' || viaLc === 'phone') {
    return nameManagedAgentSocial(input, sessionToken, onStep);
  }

  const signer = await personSignHash(input.person, viaLc, sessionToken);
  if (typeof signer !== 'function') return { ok: false, error: signer.error };
  const signHash: SignHash = signer;

  const claim = await buildClaimCallData(input.label, input.agent, onStep, true, {
    agentKind: agentClassOf(input.kind), // see the note at the charter path — one classifier, never a list
    displayName: `${input.label.replace(/\.(impact|demo\.agent)$/i, '')}.${typedTldForKind(input.kind)?.tld ?? AGENT_NAME_PARENT}`,
  }, typedTldForKind(input.kind) ?? {}); // EXACT or fail
  if (!claim.ok) return { ok: false, error: claim.error };

  onStep?.('Naming your agent on the network…');
  const res = await executeCall(input.agent, signHash, buildExecuteBatchCallData(claim.calls), { attempts: 6 });
  if (!res.ok) return { ok: false, error: `naming failed: ${res.error}` };

  onStep?.('Saving the name…');
  const save = await fetch('/connect/related-orgs', {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${sessionToken}` },
    // Only orgName changes; the server MERGES so kind/parent/stewardshipDelegation are preserved.
    body: JSON.stringify({ person: input.person, orgAgent: input.agent, orgName: claim.name, kind: input.kind, parent: input.parent }),
  });
  invalidateRelatedOrgs(); // this write changed the person's agents — the shared read must not serve the old payload
  if (!save.ok) {
    const e = (await save.json().catch(() => ({}))) as { error?: string };
    return { ok: false, error: `named on-chain (${claim.name}) but vault save failed: ${e.error ?? save.status}` };
  }
  requestReindex([input.agent]); // auto-index: the now-named managed agent appears in discovery
  return { ok: true, name: claim.name };
}

/** Resolve an EXACT label to { label, node } or fail (MAM-D4) — for the social server paths that
 *  hand the worker a pre-checked name to register. */
async function resolveExactName(label: string, tld?: string): Promise<{ ok: true; label: string; node: Hex } | { ok: false; error: string }> {
  const clean = label.trim().toLowerCase();
  // The suffix must ride along: `node` is the namehash UNDER a root, so resolving without one returns
  // the legacy `.impact` node and the claim lands there no matter what the form promised.
  const q = `/connect/name?exact=1&label=${encodeURIComponent(clean)}${tld ? `&tld=${encodeURIComponent(tld)}` : ''}`;
  const picked = (await (await fetch(q)).json()) as {
    label?: string; node?: Hex; error?: string; taken?: boolean;
  };
  if (!picked.label || !picked.node) {
    if (picked.taken) return { ok: false, error: `“${clean}.${tld ?? AGENT_NAME_PARENT}” is already taken — pick another name.` };
    return { ok: false, error: picked.error ?? 'no free name' };
  }
  return { ok: true, label: picked.label, node: picked.node };
}

/** SOCIAL create (Google / YouVersion): the worker derives C_sub + deploys the child SA (named or
 *  nameless) + approves the stewardship grant in one sponsored userOp; we record the vault link. */
async function createManagedAgentSocial(
  input: { kind: AgentKind; label?: string; parent: Address; person: Address; via: string; steward?: Address },
  sessionToken: string,
  onStep?: (s: string) => void,
): Promise<{ ok: true; result: CreateManagedAgentResult } | { ok: false; error: string }> {
  // spec 346 — the suffix names the derived agent TYPE, so it is part of what the member asked for.
  // The KMS path used to drop it here and the worker defaulted to the legacy root: the form offered
  // ".org" and produced `<label>.impact`, an agent with no declared type (2026-08-31).
  const typed = typedTldForKind(input.kind);
  const wantName = !!input.label && input.label.trim().length >= 3;
  let label: string | undefined;
  let node: Hex | undefined;
  if (wantName) {
    onStep?.('Checking that name…');
    const r = await resolveExactName(input.label!, typed?.tld);
    if (!r.ok) return r;
    label = r.label; node = r.node;
  }

  onStep?.(wantName ? 'Deploying your agent — name + access grant…' : 'Deploying your agent (unnamed)…');
  await ensureCsrfToken();
  const res = await fetch('/a2a/custody/oidc/bootstrap-agent', {
    method: 'POST',
    credentials: 'include',
    headers: { 'content-type': 'application/json', ...csrfHeaders() },
    // The worker's `parent` is the STEWARDSHIP delegate (it pre-approves child → parent in the deploy batch and
    // uses it for nothing else), so a split steward goes there; the tree's parent is written on the link below.
    body: JSON.stringify({ session: sessionToken, kind: input.kind, parent: input.steward ?? input.parent, label, node, tld: typed?.tld, serviceRole: typed?.serviceRole }),
  });
  const b = (await res.json().catch(() => ({}))) as {
    ok?: boolean; agent?: Address; name?: string; stewardshipDelegation?: DelegationWire; custodyDescriptor?: unknown; error?: string; detail?: string;
  };
  if (!res.ok || !b.ok || !b.agent) {
    return { ok: false, error: [b.error, b.detail].filter(Boolean).join(' — ') || `create failed (HTTP ${res.status})` };
  }
  const child = b.agent;
  const name = b.name ?? '';

  onStep?.('Saving to your private vault…');
  const credential = buildRelatedAgentCredential({
    holder: input.parent, relatedAgent: child, purpose: input.kind, requestedBy: '',
    issuerCaip10: `eip155:${CHAIN_ID}:${input.person}`, body: { agentName: name }, validFrom: new Date().toISOString(),
  });
  const proofHash = relatedAgentProofHash(credential);
  const save = await fetch('/connect/related-orgs', {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${sessionToken}` },
    body: JSON.stringify({
      person: input.person, orgAgent: child, orgName: name, purpose: input.kind, kind: input.kind, parent: input.parent,
      stewardshipDelegation: b.stewardshipDelegation, proofHash, custody: b.custodyDescriptor,
    }),
  });
  invalidateRelatedOrgs(); // this write changed the person's agents — the shared read must not serve the old payload
  if (!save.ok) {
    const e = (await save.json().catch(() => ({}))) as { error?: string };
    return { ok: false, error: `agent deployed${name ? ` (${name})` : ''} but saving the link failed: ${e.error ?? save.status}` };
  }
  requestReindex([child]); // auto-index: the new managed agent (treasury/org, Google path) appears now
  // Creator = first member (same as the device-credential path): C_sub signs, zero prompts.
  if (input.kind === 'org') {
    onStep?.('Adding you as the first member…');
    await recordOrgMembership(input.person, child, googleSignHash(input.person, sessionToken), sessionToken);
    // Spec 410 §8 — the founder's own membership credential. The KMS custodian signs for the SAs it custodies: the
    // person's signature comes from her signer; the organization's from a signer bound to the organization.
    try { const f = await issueFounderCredential(input.person, child, googleSignHash(input.person, sessionToken), sessionToken, { role: 'founder' }, googleSignHash(child, sessionToken)); if (!f.ok) console.warn('[org-create] the founder\'s membership credential was not issued:', f.error); }
    catch (e) { console.warn('[org-create] the founder\'s membership credential was not issued:', e); }
  }
  return { ok: true, result: { agent: child, name, kind: input.kind, parent: input.parent, stewardshipDelegation: b.stewardshipDelegation } };
}

/** SOCIAL name-later (Google / YouVersion): the worker's C_sub signs register+setPrimary AS the agent. */
async function nameManagedAgentSocial(
  input: { agent: Address; label: string; kind: AgentKind; parent: Address; person: Address; via: string },
  sessionToken: string,
  onStep?: (s: string) => void,
): Promise<{ ok: true; name: string } | { ok: false; error: string }> {
  const typed = typedTldForKind(input.kind);
  onStep?.('Checking that name…');
  const r = await resolveExactName(input.label, typed?.tld);
  if (!r.ok) return r;

  onStep?.('Naming your agent on the network…');
  await ensureCsrfToken();
  const res = await fetch('/a2a/custody/oidc/name-agent', {
    method: 'POST',
    credentials: 'include',
    headers: { 'content-type': 'application/json', ...csrfHeaders() },
    body: JSON.stringify({ session: sessionToken, agent: input.agent, label: r.label, node: r.node, tld: typed?.tld, serviceRole: typed?.serviceRole }),
  });
  const b = (await res.json().catch(() => ({}))) as { ok?: boolean; name?: string; error?: string; detail?: string };
  if (!res.ok || !b.ok || !b.name) {
    return { ok: false, error: [b.error, b.detail].filter(Boolean).join(' — ') || `naming failed (HTTP ${res.status})` };
  }

  onStep?.('Saving the name…');
  const save = await fetch('/connect/related-orgs', {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${sessionToken}` },
    body: JSON.stringify({ person: input.person, orgAgent: input.agent, orgName: b.name, kind: input.kind, parent: input.parent }),
  });
  invalidateRelatedOrgs(); // this write changed the person's agents — the shared read must not serve the old payload
  if (!save.ok) {
    const e = (await save.json().catch(() => ({}))) as { error?: string };
    return { ok: false, error: `named on-chain (${b.name}) but vault save failed: ${e.error ?? save.status}` };
  }
  requestReindex([input.agent]); // auto-index: the now-named managed agent (Google path) appears
  return { ok: true, name: b.name };
}

/** Reconcile the member's person-treasury from the AUTHORITATIVE on-chain naming registry when the
 *  related-orgs projection misses it (observed 2026-07-17: the portal shows the treasury but the
 *  connect ceremony's listManagedAgents view lacks it, so x402-pay silently skipped the payment leg).
 *  Portal naming convention: `<label>-treasury.<tld>`. Reconciling a projection from its source is
 *  not a fallback mechanism (ADR-0013). Returns null when the name doesn't resolve. */
export async function resolveTreasuryByConvention(memberName: string | undefined): Promise<Address | null> {
  const m = (memberName ?? '').trim().toLowerCase();
  const dot = m.indexOf('.');
  if (!m || dot <= 0) return null;
  const candidate = `${m.slice(0, dot)}-treasury${m.slice(dot)}`;
  try {
    const { AgentNamingClient } = await import('@agenticprimitives/agent-naming');
    const naming = new AgentNamingClient({
      rpcUrl: DEFAULT_RPC_URL,
      chainId: CHAIN_ID,
      registry: CONTRACTS.agentNameRegistry,
      universalResolver: CONTRACTS.agentNameUniversalResolver,
    });
    return ((await naming.resolveName(candidate)) as Address | null) ?? null;
  } catch {
    return null;
  }
}

/** ONE in-flight read of `/connect/related-orgs`, shared by every caller.
 *
 *  Two projections (`listMyOrgs` and `listManagedAgents`) read the SAME payload, and a single page
 *  mounts several components that each want it — the card page fired THREE identical requests and the
 *  server answered them one after another, so the page's own data did not start loading for 3.4s.
 *
 *  This is a cache, not a fallback (ADR-0013): it holds the canonical answer from the one read path, it
 *  never substitutes a different mechanism, and a failed read is never cached — the next caller retries.
 *  Writes invalidate it directly (below), so correctness does not depend on a UI event firing. */
const RELATED_ORGS_TTL_MS = 60_000; // raised from 10s (2026-10-02): page loads exceed 10s so the old TTL never hit; the tree rarely changes within a minute and every mutating write calls invalidateRelatedOrgs().
type RelatedOrgsBody = { orgs?: Array<Record<string, unknown>> };
let relatedOrgsCache: { token: string; at: number; body: RelatedOrgsBody } | null = null;
let relatedOrgsInFlight: { token: string; p: Promise<RelatedOrgsBody> } | null = null;
/** A persona's own links (`?for=`), cached by (token, persona) like the person's own. */
const relatedOrgsForCache = new Map<string, { at: number; body: RelatedOrgsBody }>();

/** Drop the shared payload — call after ANY write that changes the person's agents. */
export function invalidateRelatedOrgs(): void {
  relatedOrgsCache = null;
  relatedOrgsInFlight = null;
  relatedOrgsForCache.clear();
}

/** The links of a PERSONA of this custodian (the server checks the 'self' link; refused by name otherwise). */
async function readRelatedOrgsFor(token: string, forAgent: string): Promise<RelatedOrgsBody> {
  const key = `${token}|${forAgent.toLowerCase()}`;
  const hit = relatedOrgsForCache.get(key);
  if (hit && Date.now() - hit.at < RELATED_ORGS_TTL_MS) return hit.body;
  const r = await fetch(`/connect/related-orgs?for=${encodeURIComponent(forAgent.toLowerCase())}`, { headers: { authorization: `Bearer ${token}` } });
  const body = (await r.json().catch(() => ({}))) as RelatedOrgsBody & { error?: string };
  if (!r.ok) throw new Error(body.error ?? `related-orgs failed (HTTP ${r.status})`);
  relatedOrgsForCache.set(key, { at: Date.now(), body });
  return body;
}

async function readRelatedOrgs(token: string): Promise<RelatedOrgsBody> {
  const fresh = relatedOrgsCache;
  if (fresh && fresh.token === token && Date.now() - fresh.at < RELATED_ORGS_TTL_MS) return fresh.body;
  const flying = relatedOrgsInFlight;
  if (flying && flying.token === token) return flying.p;
  const p = (async (): Promise<RelatedOrgsBody> => {
    const r = await fetch('/connect/related-orgs', { headers: { authorization: `Bearer ${token}` } });
    if (!r.ok) throw new Error(`related-orgs failed (HTTP ${r.status})`);
    return (await r.json().catch(() => ({}))) as RelatedOrgsBody;
  })();
  relatedOrgsInFlight = { token, p };
  try {
    const body = await p;
    relatedOrgsCache = { token, at: Date.now(), body };
    return body;
  } finally {
    if (relatedOrgsInFlight?.p === p) relatedOrgsInFlight = null;
  }
}

/** List the member's managed agents (all kinds) from their home vault — one read path
 *  (the same /connect/related-orgs the orgs view already uses, MAM-D7).
 *
 *  spec 342 — lifecycle-filtered at the read boundary, and the filter CASCADES: an org-treasury
 *  whose parent org is hidden goes with it, so a deleted org can't reappear as a parent label. */
export async function listManagedAgents(sessionToken: string, surface: OrgSurface = 'working'): Promise<ManagedAgent[]> {
  const b = (await readRelatedOrgs(sessionToken).catch(() => ({}))) as RelatedOrgsRows;
  return managedAgentsFrom(b, surface);
}

/** A PERSONA's managed agents — what SHE stewards and belongs to — read by her custodian (server `?for=`). Throws when
 *  the address is not a person of theirs, so a graph never shows an empty ring for a refused read. */
export async function listManagedAgentsFor(sessionToken: string, persona: string, surface: OrgSurface = 'any'): Promise<ManagedAgent[]> {
  const b = (await readRelatedOrgsFor(sessionToken, persona)) as RelatedOrgsRows;
  return managedAgentsFrom(b, surface);
}

type RelatedOrgsRows = { orgs?: Array<{ orgAgent: Address; orgName: string; kind?: string; parent?: Address; governor?: Address; createdAt: number | null; proofHash?: string; relationship?: string; stewardshipDelegation?: unknown; status?: string; purpose?: string; nameIsLocal?: boolean }> };

function managedAgentsFrom(b: RelatedOrgsRows, surface: OrgSurface): ManagedAgent[] {
  const rows = (b.orgs ?? []).map((o) => ({
    agent: o.orgAgent,
    name: o.orgName,
    kind: (o.kind ?? 'org') as AgentKind,
    parent: (o.parent ?? ('' as Address)) as Address,
    createdAt: o.createdAt,
    proofHash: o.proofHash,
    relationship: (o.relationship === 'member' ? 'member' : o.relationship === 'self' ? 'self' : 'steward') as 'steward' | 'member' | 'self',
    ...(o.purpose ? { purpose: o.purpose } : {}),
    ...(o.stewardshipDelegation ? { stewardshipDelegation: o.stewardshipDelegation } : {}),
    ...(o.status ? { status: o.status as OrgLifecycleStatus } : {}),
    ...(o.governor ? { governor: o.governor } : {}),
    ...(o.nameIsLocal ? { nameIsLocal: true } : {}),
  }));
  return filterByLifecycle(rows, surface);
}

const MINT_ABI = [
  { type: 'function', name: 'mint', stateMutability: 'nonpayable', inputs: [{ name: 'to', type: 'address' }, { name: 'amount', type: 'uint256' }], outputs: [] },
] as const;

/** Fund a treasury with demo USDC. MockUSDC.mint is permissionless, so the member's HOME SA executes
 *  `mint(treasury, amount)` in ONE gasless sponsored userOp. The home SA is the single SA EVERY credential
 *  can sign for — passkey (passkeySignHash), wallet (personalSign), and SOCIAL (googleSignHash signs for
 *  the home SA, spec 235 §5.4). No wallet transaction → no MetaMask/Blockaid prompt. */
/**
 * The signer for a ceremony this PERSON authorizes.
 *
 * A seeded demo person has a wallet CREDENTIAL but no wallet in this browser — their custodian key is held
 * by the Home. `createManagedAgent` learned that; `fundTreasury` and `nameManagedAgent` did not, so funding
 * a demo persona's treasury opened MetaMask under a blurb promising no wallet prompt, and the popup was for
 * an account that does not custody anything here. One helper, so the next ceremony cannot forget it.
 */
export async function personSignHash(person: Address, via: string, sessionToken: string): Promise<SignHash | { error: string }> {
  const viaLc = (via ?? '').toLowerCase();
  if (viaLc === 'google' || viaLc === 'youversion' || viaLc === 'email' || viaLc === 'phone') {
    return googleSignHash(person, sessionToken); // C_sub signs for the home SA (the whole KMS family)
  }
  if (viaLc === 'wallet') {
    if (sessionToken && (await isDemoCustodyHome(sessionToken))) return demoCustodySignHash(sessionToken);
    const owner = await connectWallet();
    return (h: Hex) => personalSign(owner, h);
  }
  if (!loadPasskey()) return { error: 'Your passkey isn’t on this device — sign in to your home first.' };
  return passkeySignHash;
}

/** Does this session sign without a device prompt? (KMS homes and Home-custodied demo personas.) */
export async function signsWithoutPrompt(via: string, sessionToken: string): Promise<boolean> {
  const viaLc = (via ?? '').toLowerCase();
  if (viaLc === 'google' || viaLc === 'youversion' || viaLc === 'email' || viaLc === 'phone') return true;
  if (viaLc === 'wallet') return !!sessionToken && (await isDemoCustodyHome(sessionToken).catch(() => false));
  return false;
}

// `fundTreasury` (the browser-built mint userOp) retired 2026-09-06 — the Fund button goes through
// the harness (`home/fund-harness.ts`), one implementation with the Ask (spec 361 I4). deletes > deprecations.

/** spec 256 — org-create for a GOOGLE member: the org is custodied by their per-(iss,sub) KMS
 *  custodian C_sub and deployed + named + grant-approved SERVER-SIDE in one C_sub-signed userOp —
 *  ZERO device prompts (their only gesture was signing in with Google). Mirrors createChildAgentForSite's
 *  RESULT shape so `createOrganization` consumes both paths identically. The org's outbound grants come
 *  back from the server as 0x03 sentinel wire delegations (validated via the org SA's approved-hash
 *  branch); the private related-agent credential is built client-side (no prompt). */
export async function createOrganizationWithGoogle(
  sessionToken: string,
  base: string,
  delegate: Address,
  cOpts: CreateChildOpts = {},
  _via: string = 'google',
  onStep?: (s: string) => void,
): Promise<{ ok: true; result: CreatedAgent } | { ok: false; error: string }> {
  // Resolve a free org name (label + node), like secureHomeWithGoogle does.
  onStep?.('Finding a unique name…');
  // spec 346 — an organization claims the ORG root where this deployment offers it.
  const typed = typedTldForKind('org');
  const picked = (await (await fetch(`/connect/name?base=${encodeURIComponent(base)}${typed?.tld ? `&tld=${encodeURIComponent(typed.tld)}` : ''}`)).json()) as {
    label?: string; name?: string; node?: Hex; error?: string;
  };
  if (!picked.label || !picked.name || !picked.node) return { ok: false, error: picked.error ?? 'no free name' };

  await ensureCsrfToken();
  onStep?.('Starting the organization…');
  const res = await fetch('/a2a/custody/oidc/bootstrap-org', {
    method: 'POST',
    credentials: 'include',
    headers: { 'content-type': 'application/json', ...csrfHeaders() },
    body: JSON.stringify({ session: sessionToken, label: picked.label, node: picked.node, delegate, grantOrg: cOpts.grantOrg, tld: typed?.tld }),
  });
  const b = (await res.json().catch(() => ({}))) as {
    ok?: boolean; org?: Address; name?: string; person?: Address;
    delegation?: DelegationWire; brokerDelegation?: DelegationWire; stewardshipDelegation?: DelegationWire;
    error?: string; detail?: string;
  };
  if (!res.ok || !b.ok || !b.org || !b.person || !b.delegation) {
    return { ok: false, error: [b.error, b.detail].filter(Boolean).join(' — ') || `org bootstrap failed (HTTP ${res.status})` };
  }

  const childAgent = b.org;
  const personAgent = b.person;
  const childName = b.name ?? picked.name;
  // The public naming metadata (resolver addr / kind / display name) is its own userOp from the org: best-effort,
  // and from 2026-10-22 NOT awaited here — it was a 3–5 s chain wait on the critical path of every org-create. It
  // runs beside the org's vault and plane setup (nothing there reads these records, and nothing else sends a
  // userOp from the org SA in that window); createOrganization awaits it before the ceremony returns, so the tab
  // never leaves it behind.
  const node = picked.node; // narrowed above; a closure does not keep that narrowing
  const pendingWrites = (async () => {
    try {
      const signHash = googleSignHash(childAgent, sessionToken);
      const writes = buildNameRecordCalls(node, childAgent, childDiscoveryRecords(base, cOpts));
      const wr = await executeCalls(childAgent, signHash, writes);
      if (!wr.ok) console.warn('[org-create] public naming metadata write failed:', wr.error);
    } catch (e) {
      console.warn('[org-create] public naming metadata write failed:', e);
    }
  })();
  const relationshipType = RELATIONSHIP_TYPE.HAS_GOVERNANCE_OVER as RelationshipType;
  const edgeId = computeEdgeId(personAgent, childAgent, relationshipType);
  const purpose = cOpts.purpose ?? 'related-org';
  const requestedBy = cOpts.requestedBy ?? '';
  // ADR-0025 / spec 246: the private, self-issued related-agent credential — built client-side (no prompt).
  const credential = buildRelatedAgentCredential({
    holder: personAgent,
    relatedAgent: childAgent,
    purpose,
    requestedBy,
    issuerCaip10: `eip155:${CHAIN_ID}:${personAgent}`,
    body: { agentName: childName },
    validFrom: new Date().toISOString(),
  });
  const proofHash = relatedAgentProofHash(credential);

  // The ORG READ grant (whitelabel org_read_grant) — the passkey/wallet path folds this into the
  // deploy batch; here the org deployed server-side, so the KMS C_sub signs it directly (still zero
  // prompts). Best-effort like the naming write: a failed mint is re-run at the next select-existing.
  let readGrantDelegation: DelegationWire | undefined;
  const orgReadCfg = getClient(requestedBy)?.org_read_grant;
  if (orgReadCfg && orgReadCfg.delegate.toLowerCase() !== delegate.toLowerCase()) {
    try {
      readGrantDelegation = toWire(
        await issueOrgReadDelegation(childAgent, orgReadCfg.delegate as Address, orgReadCfg, googleSignHash(childAgent, sessionToken)),
      );
    } catch (e) {
      console.warn('[org-create] org read grant not minted:', e);
    }
  }

  return {
    ok: true,
    result: {
      childAgent, childName, edgeId, governed: false,
      delegation: b.delegation, // org → app site grant (sentinel wire)
      person: personAgent, purpose, requestedBy, credential, proofHash,
      brokerDelegation: b.brokerDelegation,
      membershipDelegation: undefined, // deferred (person→org), same as the passkey path
      stewardshipDelegation: b.stewardshipDelegation,
      readGrantDelegation,
      pendingWrites,
    },
  };
}

// ── Add a second custody credential to an existing agent (the unification) ──
//
// The canonical SA address never changes; credentials are facets that can be added.
// `addCustodian` / `addPasskey` are `onlySelf` on AgentAccount, so the EXISTING
// credential signs an `execute(self, addX(...))` UserOp. After this the agent is
// reachable by NAME via either credential (connectWithName verifies isCustodian),
// and name-info reports both. (ADR-0011: credentials rotate, identity persists.)

const ADD_CUSTODIAN_ABI = [
  { type: 'function', name: 'addCustodian', stateMutability: 'nonpayable', inputs: [{ name: 'owner', type: 'address' }], outputs: [] },
] as const;
const ADD_PASSKEY_ABI = [
  {
    type: 'function',
    name: 'addPasskey',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'credentialIdDigest', type: 'bytes32' },
      { name: 'x', type: 'uint256' },
      { name: 'y', type: 'uint256' },
      // F-2 (spec 300 / H7-C.1): the contract's addPasskey is 4-arg — the rpIdHash
      // pins the credential's RP. Omitting it made add-passkey/enroll/device-link revert.
      { name: 'rpIdHash', type: 'bytes32' },
    ],
    outputs: [],
  },
] as const;

// Removal is the symmetric `onlySelf` op: the CURRENT credential signs `execute(self, removeX)`.
// The contract refuses to remove the LAST credential (CannotRemoveLastCustodian), so you can't
// lock yourself out. (ADR-0011: credentials rotate; the SA address never changes.)
const REMOVE_CREDENTIAL_ABI = [
  { type: 'function', name: 'removeCustodian', stateMutability: 'nonpayable', inputs: [{ name: 'owner', type: 'address' }], outputs: [] },
  { type: 'function', name: 'removePasskey', stateMutability: 'nonpayable', inputs: [{ name: 'credentialIdDigest', type: 'bytes32' }], outputs: [] },
] as const;
const CREDENTIAL_READ_ABI = [
  { type: 'function', name: 'custodianCount', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint256' }] },
  { type: 'function', name: 'passkeyCount', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint256' }] },
  { type: 'function', name: 'isCustodian', stateMutability: 'view', inputs: [{ name: 'account', type: 'address' }], outputs: [{ type: 'bool' }] },
] as const;

/** Live credential counts (custodians = EOA + passkey-identity addresses; passkeys = WebAuthn keys).
 *  A view call through the demo-a2a /rpc proxy — never a log scan (ADR-0012). */
export async function readCredentialCounts(personAgent: Address): Promise<{ custodians: number; passkeys: number }> {
  const pub = createPublicClient({ chain: CHAIN, transport: http('/a2a/rpc') });
  const [c, p] = await Promise.all([
    pub.readContract({ address: personAgent, abi: CREDENTIAL_READ_ABI, functionName: 'custodianCount' }) as Promise<bigint>,
    pub.readContract({ address: personAgent, abi: CREDENTIAL_READ_ABI, functionName: 'passkeyCount' }) as Promise<bigint>,
  ]);
  return { custodians: Number(c), passkeys: Number(p) };
}

/** Remove a WALLET (EOA) custodian. The current credential signs `execute(self, removeCustodian)`. */
export async function removeWalletCredential(
  personAgent: Address,
  owner: Address,
  signHash: SignHash,
): Promise<{ ok: true; txHash?: Hex } | { ok: false; error: string }> {
  const inner = encodeFunctionData({ abi: REMOVE_CREDENTIAL_ABI, functionName: 'removeCustodian', args: [owner] });
  return executeCall(personAgent, signHash, buildExecuteCallData({ to: personAgent, value: 0n, data: inner }), { attempts: 5 });
}

/** Remove a PASSKEY by its credentialIdDigest. The current credential signs `execute(self, removePasskey)`. */
export async function removePasskeyCredential(
  personAgent: Address,
  credentialIdDigest: Hex,
  signHash: SignHash,
): Promise<{ ok: true; txHash?: Hex } | { ok: false; error: string }> {
  const inner = encodeFunctionData({ abi: REMOVE_CREDENTIAL_ABI, functionName: 'removePasskey', args: [credentialIdDigest] });
  return executeCall(personAgent, signHash, buildExecuteCallData({ to: personAgent, value: 0n, data: inner }), { attempts: 5 });
}

// DelegationManager.revokeDelegationByOwner(Delegation) — authenticated revoke: msg.sender
// MUST be the delegation's delegator (or delegate). We route it through the DELEGATOR SA's
// `execute`, so the on-chain msg.sender is the delegator and the gate passes. The contract
// re-verifies the struct's signature before marking the hash revoked. `args` is excluded
// from the signed hash (CAVEAT_TYPEHASH = enforcer+terms), so '0x' here is fine.
const REVOKE_DELEGATION_ABI = [
  {
    type: 'function',
    name: 'revokeDelegationByOwner',
    stateMutability: 'nonpayable',
    inputs: [
      {
        name: 'delegation',
        type: 'tuple',
        components: [
          { name: 'delegator', type: 'address' },
          { name: 'delegate', type: 'address' },
          { name: 'authority', type: 'bytes32' },
          {
            name: 'caveats',
            type: 'tuple[]',
            components: [
              { name: 'enforcer', type: 'address' },
              { name: 'terms', type: 'bytes' },
              { name: 'args', type: 'bytes' },
            ],
          },
          { name: 'salt', type: 'uint256' },
          { name: 'signature', type: 'bytes' },
        ],
      },
    ],
    outputs: [],
  },
] as const;

/**
 * Revoke a delegation the person granted (ADR-0019: relying-site authority is a revocable
 * scoped delegation). The DELEGATOR SA (`d.delegator` — the person SA, or an org the person
 * custodies) signs `execute(DelegationManager, revokeDelegationByOwner(d))`, so the on-chain
 * `msg.sender` is the delegator and the authenticated gate passes. After this lands,
 * `isRevoked(hash)` is true and `verifyDelegationToken` rejects the delegation — the grantee's
 * access is gone. `signHash` is the person's credential (it custodies both the person SA and
 * its org SAs as siblings, so the same credential validates either delegator's ERC-1271).
 */
export async function revokeGrantedDelegation(
  d: DelegationWire,
  signHash: SignHash,
): Promise<{ ok: true; txHash?: Hex } | { ok: false; error: string }> {
  const onchainDelegation = {
    delegator: d.delegator,
    delegate: d.delegate,
    authority: d.authority,
    caveats: d.caveats.map((c) => ({ enforcer: c.enforcer, terms: c.terms, args: c.args ?? '0x' })),
    salt: BigInt(d.salt),
    signature: d.signature,
  } as const;
  const inner = encodeFunctionData({
    abi: REVOKE_DELEGATION_ABI,
    functionName: 'revokeDelegationByOwner',
    args: [onchainDelegation],
  });
  return executeCall(
    d.delegator,
    signHash,
    buildExecuteCallData({ to: CONTRACTS.delegationManager, value: 0n, data: inner }),
    { attempts: 5 },
  );
}

/** Add a WALLET (EOA) custodian to an agent currently controlled by a PASSKEY.
 *  Connects the wallet to add + proves control of it (personal_sign), then the
 *  EXISTING passkey signs `execute(self, addCustodian(newEoa))`. */
export async function addWalletCredential(
  personAgent: Address,
  authorizerSignHash: SignHash, // the CURRENT custodian authorizes the on-chain add (passkey / wallet / KMS)
  onStep?: (s: string) => void,
): Promise<{ ok: true; added: Address } | { ok: false; error: string }> {
  onStep?.('Connecting the wallet to add…');
  const addr = await connectWallet();
  onStep?.('Confirm with the wallet you’re adding…');
  await personalSign(addr, `Add this wallet as a custodian of ${personAgent} on Agentic Connect.`);

  const inner = encodeFunctionData({ abi: ADD_CUSTODIAN_ABI, functionName: 'addCustodian', args: [addr] });
  const callData = buildExecuteCallData({ to: personAgent, value: 0n, data: inner });
  onStep?.(`Adding ${addr.slice(0, 6)}…${addr.slice(-4)} — confirming with your current sign-in…`);
  const res = await executeCall(personAgent, authorizerSignHash, callData, { attempts: 5 });
  if (!res.ok) return { ok: false, error: res.error };
  return { ok: true, added: addr };
}

/** Add a PASSKEY custodian. Registers a fresh passkey on this device, then the agent's CURRENT custodian
 *  signs `execute(self, addPasskey(digest, x, y))`. The authorizer is whatever secures the home today —
 *  a wallet (MetaMask), a passkey, OR a KMS/Google/email custodian (signed server-side, no device prompt) —
 *  so this must NOT assume a wallet (that popped MetaMask for KMS-custodied homes, which have none). */
export async function addPasskeyCredential(
  personAgent: Address,
  authorizerSignHash: SignHash,
  onStep?: (s: string) => void,
): Promise<{ ok: true; credentialIdDigest: Hex } | { ok: false; error: string }> {
  onStep?.('Creating the passkey to add…');
  const pk = await registerPasskey(`${personAgent.slice(0, 8)}… passkey`); // fresh passkey, stored on this device

  const rpIdHash = await derivePasskeyRpIdHash(); // must match the value used at registration (sha256(passkeyRpId()))
  const inner = encodeFunctionData({
    abi: ADD_PASSKEY_ABI,
    functionName: 'addPasskey',
    args: [pk.credentialIdDigest, pk.pubKeyX, pk.pubKeyY, rpIdHash],
  });
  const callData = buildExecuteCallData({ to: personAgent, value: 0n, data: inner });
  onStep?.('Adding the passkey — confirming with your current sign-in…');
  const res = await executeCall(personAgent, authorizerSignHash, callData, { attempts: 5 });
  if (!res.ok) return { ok: false, error: res.error };
  return { ok: true, credentialIdDigest: pk.credentialIdDigest };
}

/** Central-auth enrollment (spec 229 §5): add a RELYING SITE's PROVIDED local passkey
 *  (PUBLIC key only) as a custodian of `name`'s agent, signed by THIS origin's primary
 *  passkey. The site's private key never leaves the site's device — we only register its
 *  (x, y). This is how a new origin gets its own per-site signer without reusing the
 *  central credential. Fails closed: addPasskey only validates if the primary passkey is
 *  already a custodian of the agent. */
export async function enrollSitePasskey(
  name: string,
  enroll: { credentialIdDigest: Hex; x: bigint; y: bigint },
  onStep?: (s: string) => void,
): Promise<{ ok: true; agent: Address; name: string } | { ok: false; error: string }> {
  onStep?.('Resolving your agent…');
  const r = await fetch(`/connect/name-info?name=${encodeURIComponent(name)}`);
  const info = (await r.json()) as { exists?: boolean; name?: string; agent?: Address };
  if (!info.exists || !info.agent) return { ok: false, error: `no agent named ${name}` };
  const rpIdHash = await derivePasskeyRpIdHash(); // must match the value used at registration (sha256(passkeyRpId()))
  const inner = encodeFunctionData({
    abi: ADD_PASSKEY_ABI,
    functionName: 'addPasskey',
    args: [enroll.credentialIdDigest, enroll.x, enroll.y, rpIdHash],
  });
  const callData = buildExecuteCallData({ to: info.agent, value: 0n, data: inner });
  onStep?.('Approve with your passkey…');
  const res = await executeCall(info.agent, passkeySignHash, callData, { attempts: 6 });
  if (!res.ok) return { ok: false, error: res.error };
  return { ok: true, agent: info.agent, name: info.name ?? name };
}

// ── Cross-device: link a device (spec 233 P2) ───────────────────────────────
// A NEW browser/device with no passkey for this agent (its passkey RP differs)
// creates its OWN local passkey and posts a short-lived REQUEST; the ORIGINAL
// device (which holds the agent's existing passkey) approves by signing
// addPasskey via the ROOT — no self-add (the request is not a grant). Once the
// key lands on-chain, the new device discoverable-signs-in.

export interface DeviceLinkRequest {
  agent: Address;
  name: string;
  credentialIdDigest: Hex;
  x: string;
  y: string;
  label: string;
}

/** NEW DEVICE: create a fresh local passkey at this origin (RP = this host) +
 *  post a link request. Returns a short code to read to the original device. */
export async function requestDeviceLink(
  name: string,
  label?: string,
): Promise<{ ok: true; code: string; agent: Address; credentialIdDigest: Hex } | { ok: false; error: string }> {
  const info = (await (await fetch(`/connect/name-info?name=${encodeURIComponent(name)}`)).json()) as {
    exists?: boolean;
    name?: string;
    agent?: Address;
  };
  if (!info.exists || !info.agent) return { ok: false, error: `no agent named ${name}` };
  const pk = await registerPasskey(label ?? `${name} (new device)`); // fresh passkey, stored on THIS device
  const resp = await fetch('/connect/link/request', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      agent: info.agent,
      name: info.name ?? name,
      credentialIdDigest: pk.credentialIdDigest,
      x: pk.pubKeyX.toString(),
      y: pk.pubKeyY.toString(),
      label: label ?? 'New device',
    }),
  });
  const body = (await resp.json()) as { code?: string; error?: string };
  if (!resp.ok || !body.code) return { ok: false, error: body.error ?? 'link request failed' };
  return { ok: true, code: body.code, agent: info.agent, credentialIdDigest: pk.credentialIdDigest };
}

/** ORIGINAL DEVICE: fetch a pending link request by code (to show + approve). */
export async function lookupDeviceLink(
  code: string,
): Promise<{ ok: true; req: DeviceLinkRequest } | { ok: false; error: string }> {
  const r = await fetch(`/connect/link/lookup?code=${encodeURIComponent(code.trim())}`);
  const body = (await r.json()) as DeviceLinkRequest & { error?: string };
  if (!r.ok || !body.agent) return { ok: false, error: body.error ?? 'invalid or expired code' };
  return { ok: true, req: body };
}

/** ORIGINAL DEVICE: approve — the ROOT passkey signs addPasskey for the new key. */
export async function approveDeviceLink(
  req: DeviceLinkRequest,
  onStep?: (s: string) => void,
): Promise<{ ok: true } | { ok: false; error: string }> {
  const res = await enrollSitePasskey(
    req.name,
    { credentialIdDigest: req.credentialIdDigest, x: BigInt(req.x), y: BigInt(req.y) },
    onStep,
  );
  return res.ok ? { ok: true } : { ok: false, error: res.error };
}

/** NEW DEVICE: poll until the new key is a registered passkey on-chain. */
export async function pollDeviceLink(agent: Address, credentialIdDigest: Hex): Promise<boolean> {
  const r = await fetch(`/connect/link/status?agent=${agent}&digest=${credentialIdDigest}`);
  if (!r.ok) return false;
  return ((await r.json()) as { enrolled?: boolean }).enrolled === true;
}

/** SINGLE-DEVICE add (spec 233 P2, the smooth path): on THIS device, create a new
 *  local passkey AND immediately enroll it by signing `addPasskey` with your
 *  EXISTING passkey via a DISCOVERABLE assertion. When this device holds no local
 *  passkey, the browser's discoverable prompt offers "use a passkey from another
 *  device" (WebAuthn hybrid / QR) — so you approve with the phone/computer that has
 *  it, right here, no code + no second tab. Still ROOT-authorized (the hybrid
 *  assertion IS the existing custodian approving — no self-add). Requires the
 *  approving device to be reachable for the QR; falls back to the code flow if not. */
export async function addThisDevicePasskey(
  name: string,
  onStep?: (s: string) => void,
): Promise<{ ok: true; credentialIdDigest: Hex } | { ok: false; error: string }> {
  const info = (await (await fetch(`/connect/name-info?name=${encodeURIComponent(name)}`)).json()) as {
    exists?: boolean;
    name?: string;
    agent?: Address;
  };
  if (!info.exists || !info.agent) return { ok: false, error: `no agent named ${name}` };
  onStep?.('Creating a passkey on this device…');
  const pk = await registerPasskey(`${name} (this device)`);
  const rpIdHash = await derivePasskeyRpIdHash(); // must match the value used at registration (sha256(passkeyRpId()))
  const inner = encodeFunctionData({
    abi: ADD_PASSKEY_ABI,
    functionName: 'addPasskey',
    args: [pk.credentialIdDigest, pk.pubKeyX, pk.pubKeyY, rpIdHash],
  });
  const callData = buildExecuteCallData({ to: info.agent, value: 0n, data: inner });
  onStep?.('Approve with your existing passkey — choose “another device” if asked, and scan with the device that has it.');
  const res = await executeCall(info.agent, passkeySignHash, callData, { attempts: 6 });
  if (!res.ok) return { ok: false, error: res.error };
  return { ok: true, credentialIdDigest: pk.credentialIdDigest };
}

/** Step a Google (login-grade) session UP to custody-grade for the SAME bound agent.
 *  The target agent is the googleToken's sub (server-enforced) — so a Google login can
 *  only ever step up into its one bound workspace; the credential must be a custodian of it. */
export async function stepUpToAgent(
  via: 'wallet' | 'passkey',
  googleToken: string,
): Promise<{ ok: true; token: string } | { ok: false; error: string }> {
  if (via === 'wallet') {
    const address = await connectWallet();
    const nonce = await getNonce();
    const message = buildMessage({
      domain: window.location.host,
      address,
      uri: window.location.origin,
      chainId: CHAIN_ID,
      nonce,
      statement: 'Confirm custody of your Agentic Connect workspace.',
    });
    const signature = await personalSign(address, message);
    const r = await fetch('/connect/stepup', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ googleToken, kind: 'siwe-eoa', aud: AUD, message, signature }),
    });
    const b = (await r.json()) as { status?: string; token?: string; error?: string };
    if (r.ok && b.status === 'issued' && b.token) return { ok: true, token: b.token };
    return { ok: false, error: b.error ?? `step-up failed (HTTP ${r.status})` };
  }
  const pk = loadPasskey();
  if (!pk) return { ok: false, error: 'no passkey on this device' };
  const { challenge } = (await (await fetch('/connect/passkey-challenge')).json()) as { challenge: Hex };
  const signature = await signWithPasskey(challenge);
  const r = await fetch('/connect/stepup', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ googleToken, kind: 'passkey', aud: AUD, credentialIdDigest: pk.credentialIdDigest, challenge, signature }),
  });
  const b = (await r.json()) as { status?: string; token?: string; error?: string };
  if (r.ok && b.status === 'issued' && b.token) return { ok: true, token: b.token };
  return { ok: false, error: b.error ?? `step-up failed (HTTP ${r.status})` };
}

/** Connect to the agent that OWNS `name`, proving control with a custody credential.
 *  Name-first: the agent-service name is the identity; the server resolves name→agent
 *  on-chain and verifies the credential is a custodian of it. */
/** Connect the wallet (forcing the account picker) and return the connected account that is an on-chain
 *  CUSTODIAN of `sa` — not just the active account. `eth_requestAccounts` returns the active account first,
 *  which is often a DIFFERENT home's custodian (e.g. the platform deployer), so signing by-home/by-name must
 *  select among ALL connected accounts. Throws (clear message) if none of them custodies `sa`. Shared by the
 *  by-name sign-in (connectWithName) and the relying-app grant signer (signHashFor). */
/** B5 — cache-first custodian connect. Reuse the session-cached custodian for `sa` (confirmed still connected
 *  via a SILENT `eth_accounts` read — NO picker popup) instead of re-popping MetaMask's account picker on every
 *  ceremony. Falls back to `connectCustodianWallet` (the picker + on-chain `isCustodian` validation) on a cache
 *  miss or a stale/disconnected entry, then caches the result. `restrictTo` is the durable remembered-EOA hint
 *  forwarded to the picker on the fallback. The picker thus fires ONCE per session per home, not N times. */
export async function connectCustodianCached(sa: Address, restrictTo?: Address): Promise<Address> {
  const cached = recallSessionCustodian(sa);
  if (cached) {
    const live = await connectedAccountsSilent();
    if (live.some((a) => a.toLowerCase() === cached.toLowerCase())) return cached; // still connected → no picker
  }
  const addr = await connectCustodianWallet(sa, restrictTo);
  rememberSessionCustodian(sa, addr);
  return addr;
}

export async function connectCustodianWallet(sa: Address, restrictTo?: Address): Promise<Address> {
  // `restrictTo` (the remembered custodian EOA for this home) defaults MetaMask's picker to that account —
  // helpful after a disconnect cleared its memory. It's a hint only; we still verify isCustodian on-chain.
  const accounts = await connectWalletAccounts(true, restrictTo);
  const accountsClient = agentAccountClient();
  for (const a of accounts) {
    try { if (await accountsClient.isCustodian(sa, a)) return a; } catch { /* not deployed / read error → skip */ }
  }
  // Name the EXACT account to connect when we know it (the published connection address / remembered EOA,
  // spec 280) — MetaMask can't be forced to an account, so the next-best thing is telling the user precisely
  // which one to pick. Falls back to a generic message when no expected address is known.
  const which = restrictTo
    ? `In MetaMask, open the account menu → “Connect more accounts” and connect ${restrictTo}, then retry.`
    : 'In the wallet popup, connect the account that custodies it, then retry.';
  throw new Error(`None of your connected wallets control this home. ${which} The active account isn’t a custodian.`);
}

export async function connectWithName(
  name: string,
  via: 'wallet' | 'passkey',
  opts: { passkeyMode?: 'local' | 'discoverable' } = {},
): Promise<{ ok: true; token: string; name?: string } | { ok: false; error: string }> {
  let proof: Record<string, unknown>;
  if (via === 'wallet') {
    // Sign with the wallet that actually custodies `${name}` — not MetaMask's active account (which may be
    // another home's custodian, e.g. the platform deployer). Resolve name→SA, then pick the connected
    // custodian account (connectCustodianWallet).
    const info = (await (await fetch(`/connect/name-info?name=${encodeURIComponent(name)}`)).json().catch(() => ({}))) as { agent?: Address; connectionAddress?: Address };
    if (!info.agent) return { ok: false, error: `Couldn’t resolve ${name}.` };
    let address: Address;
    // Default the picker to the EOA we last used for THIS name, falling back to the owner-PUBLISHED
    // connection address (spec 280) when local memory is empty — the cross-device / fresh-browser fix
    // (AgentAccount has no owner() to read the custodian from chain). Still validated by connectCustodianWallet.
    try { address = await connectCustodianCached(info.agent, recallHomeEoa(name) ?? info.connectionAddress); }
    catch (e) { return { ok: false, error: e instanceof Error ? e.message : 'wallet connection failed' }; }
    rememberHomeEoa(name, address); // remember the custodian EOA so next sign-in defaults straight to it
    const nonce = await getNonce();
    const message = buildMessage({
      domain: window.location.host,
      address,
      uri: window.location.origin,
      chainId: CHAIN_ID,
      nonce,
      statement: `Connect to ${name} on Agentic Connect.`,
    });
    const signature = await personalSign(address, message);
    proof = { kind: 'siwe-eoa', message, signature };
  } else {
    // Default sign-in is LOCAL-FIRST: use the cached credential id when present. If the cache is absent,
    // do not silently launch Windows' discoverable picker (it can hang then offer phone only). The explicit
    // cross-device button passes `passkeyMode:'discoverable'`.
    const { challenge } = (await (await fetch('/connect/passkey-challenge')).json()) as { challenge: Hex };
    const cached = loadPasskey();
    if (!cached && opts.passkeyMode !== 'discoverable') {
      return {
        ok: false,
        error:
          'This browser does not have the local passkey cache for this home. Use the synced/phone passkey option, or open the browser where this home was first secured.',
      };
    }
    const localFirst = opts.passkeyMode !== 'discoverable';
    let signature: Hex;
    let credentialIdDigest: Hex;
    try {
      ({ signature, credentialIdDigest } = await connectAssertionDiscoverable(challenge, { preferLocalDevice: localFirst }));
    } catch (e) {
      // The platform's own words here are "There aren't any passkeys for <host> on this device", which
      // reads as "your passkey is gone" when what it means is "not the one this browser remembers, and
      // not here". The home's passkey may be perfectly fine on a phone or in a synced store. Say which
      // of the two situations this is, and name the button that reaches the other one — the raw message
      // dead-ended a member whose passkey was registered on chain the whole time.
      const noCredential = e instanceof DOMException ? e.name === 'NotAllowedError' : /not allowed|no passkey|timed out/i.test(e instanceof Error ? e.message : String(e));
      if (!noCredential) throw e;
      return {
        ok: false,
        error: localFirst
          ? 'No passkey on this device matched the one this browser remembers. If you set it up on your phone or in a synced store, use “Use synced or phone passkey”.'
          : 'No passkey for this home was offered. Check that the device or phone holding it is available, or sign in with the credential that first opened this home.',
      };
    }
    proof = { kind: 'passkey', credentialIdDigest, challenge, signature };
  }
  const r = await fetch('/connect/with-name', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ name, aud: AUD, ...proof }),
  });
  const b = (await r.json()) as { status?: string; token?: string; name?: string; error?: string; detail?: string };
  if (r.ok && b.status === 'issued' && b.token) return { ok: true, token: b.token, name: b.name };
  // `detail` is where with-name says WHICH failure this is (an unregistered credential reads very
  // differently from a rejected signature). Dropping it left the member with a verdict and no cause.
  return { ok: false, error: [b.error, b.detail].filter(Boolean).join(' — ') || `connect failed (HTTP ${r.status})` };
}

// ── Guided ceremony steps (spec 230 part 2) ─────────────────────────
// Each step is its OWN exported call so the relying UI can gate every WebAuthn prompt behind a
// button with a promise before + a receipt after — no two prompts fire back-to-back. (signupWithName
// runs the same work in one shot; these expose the seams.)

/** Step 1 — create the person's secure-home passkey (ONE WebAuthn create). Stored on this device. */
export async function createSecureHomePasskey(name: string): Promise<DemoPasskey> {
  const base = name.replace(/\.(impact|demo\.agent)$/, '');
  return registerPasskey(`${base}.impact`);
}

/** Step 2 — deploy the person's Smart Agent + claim its name in ONE userOp (ONE WebAuthn sign). */
export async function deployAndClaimAgent(
  passkey: DemoPasskey,
  base: string,
  extraApproveDigests: Hex[] = [],
  onStep?: (s: string) => void,
): Promise<{ ok: true; agent: Address; name: string } | { ok: false; error: string }> {
  const sa = await derivePasskeySa(passkey, 0n);
  const claim = await buildClaimCallData(base, sa, undefined, false, { agentKind: 'person' }, typedTldForKind('person') ?? {});
  if (!claim.ok) return { ok: false, error: claim.error };
  // spec 253 batching — fold the person's plane-grant approveHash(digest) calls into the SAME deploy
  // userOp (deploy + claim + approve-all), so those grants need no separate signature (one passkey prompt).
  const callData = extraApproveDigests.length
    ? buildExecuteBatchCallData([...claim.calls, ...extraApproveDigests.map((d) => buildApproveHashCall(d, sa))])
    : claim.callData;
  const dep = await bootstrapWithPasskey(passkey, onStep, callData);
  if (!dep.ok) return { ok: false, error: dep.error };
  return { ok: true, agent: dep.agent, name: claim.name };
}

/** Sign up: create a workspace named `<base>.demo.agent` with a custody credential,
 *  and CLAIM the name for THAT credential's agent (so connect-by-name later offers the
 *  right credential). Passkey → a FRESH passkey (a new workspace); wallet → the EOA's
 *  agent. The claim runs whether the agent is freshly deployed or reconnected. */
export async function signupWithName(
  base: string,
  via: 'wallet' | 'passkey',
  onStep?: (s: string) => void,
  signIn = true,
  /** spec 253 batching (device vias) — given the derived person SA, return the plane-grant digests to
   *  fold into the deploy userOp + a submit() to hand the pre-approved wires to the DOs after deploy. Only
   *  the FRESH-EOA deploy path honors it (an existing agent has no deploy op to batch into). */
  buildExtra?: (sa: Address) => Promise<{ digests: Hex[]; submit: () => Promise<void> }>,
): Promise<{ ok: true; token: string; name: string; agent: Address } | { ok: false; error: string }> {
  if (via === 'passkey') {
    onStep?.('Creating your passkey…');
    const pk = await registerPasskey(`${base}.impact`); // FRESH passkey for this workspace
    // Deploy + claim the name in ONE userOp (one device prompt): derive the SA address, build
    // the claim calldata (newOwner = that SA), and deploy with it attached.
    const sa = await derivePasskeySa(pk, 0n);
    const claim = await buildClaimCallData(base, sa, onStep, false, { agentKind: 'person' }, typedTldForKind('person') ?? {});
    if (!claim.ok) return { ok: false, error: claim.error };
    const dep = await bootstrapWithPasskey(pk, onStep, claim.callData);
    if (!dep.ok) return { ok: false, error: dep.error };
    // The OIDC enrollment ceremony signs the person in via the grant + id_token, so it skips
    // this extra passkeyLogin (its token would be unused) — saving one device prompt. We return
    // the KNOWN agent address (from the deploy) so callers needn't re-resolve by name — the
    // just-claimed name lags on-chain for a moment (RPC), and `sa` is already authoritative.
    if (!signIn) return { ok: true, token: '', name: claim.name, agent: sa };
    onStep?.('Signing you in…');
    const login = await passkeyLogin(false);
    return login.status === 'issued'
      ? { ok: true, token: login.token, name: claim.name, agent: sa }
      : { ok: false, error: `created, but sign-in returned ${login.status}` };
  }
  // wallet: the EOA's deterministic agent (reconnect if it exists, else bootstrap).
  onStep?.('Connecting your wallet…');
  // B6 — DETECTION WITHOUT SIWE. The old flow spent a `siweLogin` just to learn fresh-vs-existing. Instead
  // pick the custodian account (the picker fires either way), derive its deterministic SA, and READ whether
  // it's already deployed. A fresh self-serve signup then signs ZERO SIWE before deploy — only the deploy+claim
  // userOp — and the session is issued later by `openHome` (the facet enrolls there too, like the passkey path).
  const address = await connectWallet(true);
  const sa = await deriveEoaSa(address, 0n);
  rememberSessionCustodian(sa, address); // B5 — seed the custodian cache for the ceremonies that follow
  const deployed = await isAgentDeployed(sa);
  if (deployed) {
    // Existing agent → claim the name in a standalone op (no deploy to batch it into).
    const signHash: SignHash = (h) => personalSign(address, h);
    const claim = await claimName(sa, signHash, base, onStep);
    if (!claim.ok) return { ok: false, error: claim.error };
    if (!signIn) return { ok: true, token: '', name: claim.name, agent: sa };
    onStep?.('Signing you in…');
    const login = await siweLogin();
    return login.status === 'issued'
      ? { ok: true, token: login.token, name: claim.name, agent: sa }
      : { ok: false, error: `created, but sign-in returned ${login.status}` };
  }
  // Fresh EOA → DEPLOY + CLAIM in ONE userOp (B2), NO SIWE. `deriveEoaSa` matches the server's eoa deploy
  // (custodians=[owner], salt=0); build the claim calldata (newOwner = that SA) and attach it so the SA is
  // created AND the name claimed in a SINGLE wallet prompt.
  const claim = await buildClaimCallData(base, sa, onStep, false, { agentKind: 'person' }, typedTldForKind('person') ?? {});
  if (!claim.ok) return { ok: false, error: claim.error };
  // spec 253 batching — fold the person's plane-grant approveHash(digest) calls into this deploy userOp,
  // then submit the pre-approved 0x03 wires once the SA is RPC-visible: deploy + claim + approve-all in
  // ONE wallet prompt, no per-grant signature.
  const extra = buildExtra ? await buildExtra(sa) : undefined;
  const deployCallData = extra && extra.digests.length
    ? buildExecuteBatchCallData([...claim.calls, ...extra.digests.map((d) => buildApproveHashCall(d, sa))])
    : claim.callData;
  const dep = await bootstrapWithWallet(address, onStep, deployCallData);
  if (!dep.ok) return { ok: false, error: dep.error };
  const agent = dep.agent;
  if (extra) {
    for (let i = 0; i < 20; i++) { if (await isAgentDeployed(agent).catch(() => false)) break; await new Promise((r) => setTimeout(r, fastPollMs(2000))); }
    await extra.submit();
  }
  // B1 — self-serve `secureHome` passes signIn=false; the session is issued later by openHome, so skip the
  // SIWE here (its token would be unused).
  if (!signIn) return { ok: true, token: '', name: claim.name, agent };
  onStep?.('Signing you in…');
  const login = await siweLogin();
  return login.status === 'issued'
    ? { ok: true, token: login.token, name: claim.name, agent }
    : { ok: false, error: `created, but sign-in returned ${login.status}` };
}

/** A NAMELESS wallet home (spec 257 name-deferral, extended to the wallet 2026-09-13): the EOA's deterministic
 *  person SA is deployed with NO name claimed — the public name is a later choice from the portal, exactly as
 *  a Google home is born. A returning EOA whose SA already exists just signs in. Plane grants fold into the
 *  deploy userOp (`buildExtra`, spec 253) so the whole thing is ONE wallet prompt plus the SIWE sign-in. */
export async function signupWalletNoName(
  onStep?: (s: string) => void,
  buildExtra?: (sa: Address) => Promise<{ digests: Hex[]; submit: () => Promise<void> }>,
): Promise<{ ok: true; token: string; agent: Address; fresh: boolean } | { ok: false; error: string }> {
  onStep?.('Connecting your wallet…');
  const address = await connectWallet(true);
  const sa = await deriveEoaSa(address, 0n);
  rememberSessionCustodian(sa, address);
  const deployed = await isAgentDeployed(sa);
  if (!deployed) {
    const extra = buildExtra ? await buildExtra(sa) : undefined;
    const deployCallData = extra && extra.digests.length
      ? buildExecuteBatchCallData(extra.digests.map((d) => buildApproveHashCall(d, sa)))
      : undefined;
    const dep = await bootstrapWithWallet(address, onStep, deployCallData);
    if (!dep.ok) return { ok: false, error: dep.error };
    if (extra) {
      for (let i = 0; i < 20; i++) { if (await isAgentDeployed(dep.agent).catch(() => false)) break; await new Promise((r) => setTimeout(r, fastPollMs(2000))); }
      await extra.submit();
    }
  }
  onStep?.('Signing you in…');
  const login = await siweLogin();
  return login.status === 'issued'
    ? { ok: true, token: login.token, agent: sa, fresh: !deployed }
    : { ok: false, error: `${deployed ? 'found' : 'created'}, but sign-in returned ${login.status}` };
}

export interface BasicProfile {
  agent: string;
  name: string | null;
  credential: string;
  access: string;
  /** spec 257 Phase 1.5 — is the SA deployed on-chain? false = counterfactual (fresh Google
   *  return, no home yet → secure-home); true with name === null = a nameless deferred home. */
  deployed: boolean;
  /** The on-chain read failed — `deployed` is a default, not an answer (ADR-0013). */
  deployedError?: string;
}

/**
 * A short memo of `/me/profile` per token (2026-10-21). One sign-in through to a Gather publish read it SIX times,
 * 0.2–1 s each, from the session shell, the consent screen, the client defaults and the sign-in card — the same
 * answer every time. Callers asking while a read is in flight share it; an answer is reused for ten seconds; a
 * failure is never kept. `fresh` bypasses it, for the reads that follow a change (a name claimed, a refresh).
 */
const PROFILE_MEMO_MS = 10_000;
const profileMemo = new Map<string, { at: number; value: Promise<BasicProfile | null> }>();

export async function fetchProfile(token: string, opts: { fresh?: boolean } = {}): Promise<BasicProfile | null> {
  const hit = profileMemo.get(token);
  if (!opts.fresh && hit && Date.now() - hit.at < PROFILE_MEMO_MS) return hit.value;
  const value = (async (): Promise<BasicProfile | null> => {
    const r = await fetch('/me/profile', { headers: { authorization: `Bearer ${token}` } });
    if (!r.ok) return null;
    return ((await r.json()) as { profile: BasicProfile }).profile;
  })();
  profileMemo.set(token, { at: Date.now(), value });
  value.then((p) => { if (p === null && profileMemo.get(token)?.value === value) profileMemo.delete(token); }, () => { if (profileMemo.get(token)?.value === value) profileMemo.delete(token); });
  return value;
}

/** A related org the person holds (spec 246 / ADR-0025) — read from THEIR vault for the
 *  person's own home view (all orgs, all requesting apps). Carries no person→org graph. */
export interface MyOrg {
  orgAgent: Address;
  orgName: string;
  purpose: string;
  requestedBy: string;
  createdAt: number | null;
  proofHash?: string;
  /** spec 275 — agent kind. The orgs view shows only `org` (or legacy undefined); the
   *  treasury kinds belong to the "Your agents" tree, not the organizations list. */
  kind?: AgentKind;
  /** steward = custody; member = authority-only membership (no org custody). */
  relationship?: 'steward' | 'member';
  /** spec 342 — the org's lifecycle status, PROJECTED from its `org.lifecycle` vault record so a
   *  roster can be filtered without a vault read per row. Absent means active. */
  status?: OrgLifecycleStatus;
  /** The scoped org→site delegation the person granted (absent for self-governed orgs).
   *  Carries the full wire struct so /you can revoke it (revokeGrantedDelegation). */
  delegation?: DelegationWire;
  /** spec 246 person↔org read delegations. stewardship = org→person: the person presents
   *  it to the vault to READ this org's data (the person oversees the org). membership =
   *  person→org: the org reads its member's data. */
  membershipDelegation?: DelegationWire;
  stewardshipDelegation?: DelegationWire;
}

/** An inbound grant one of the person's orgs RECEIVED (spec 247). org↔org only — no
 *  grantor person identity (ADR-0025). `viaOrg` is the person's org that holds it. */
export interface ReceivedDelegation {
  viaOrg: Address;
  viaOrgName: string;
  orgAgent: Address;
  orgName: string;
  /** spec 321 item-2 — the display name the member chose at join (roster label). */
  displayName?: string;
  /** The grantor→viaOrg delegation (delegator = the member org), so the governing person
   *  can read that member's vault over it (spec 247). */
  delegation?: DelegationWire;
}

/** List the inbound delegations the person's orgs received, for the /you delegations
 *  view. Person-session-authorized (same-origin, the home session token). */
export async function listMyReceivedDelegations(token: string): Promise<ReceivedDelegation[]> {
  const r = await fetch('/connect/received-delegations', { headers: { authorization: `Bearer ${token}` } });
  if (!r.ok) return [];
  const b = (await r.json().catch(() => ({}))) as { received?: ReceivedDelegation[] };
  return b.received ?? [];
}

/** Register a named agent into the discovery registry (spec 279), ALL-CUSTODIAN. The agent's own SA
 *  executes `registerEntry` (RB-01: msg.sender == subjectAgent), signed by `signHash` (the same passkey/
 *  wallet/KMS credential the home uses for delegations + payments) and sponsored by the paymaster, gasless
 *  via `executeCall` — ONE custody prompt. The entry's cardHash + bindingProofHash are hashes of the card
 *  + binding-proof BODIES (no extra signature needed on-chain); the SA-signed bundles for off-chain
 *  re-verification are a follow-on (publish-by-hash). The registry this Home lists into is open (no
 *  membership hook), so any agent may self-register.
 *
 *  WHICH registry is a DEPLOYMENT fact, never a constant. It was hardcoded to production's
 *  `urn:ap:registry:impact-agents`, so the faithnet Home offered to register its agents into a registry
 *  on another chain — a WRITE, signed by the agent's own account, into the wrong place. Unset now means
 *  registration is not offered at all, which is the honest failure: better to say this Home has no
 *  directory configured than to write into somebody else's. */
export const DISCOVERY_REGISTRY_ID = AGENT_REGISTRY_URN;
export async function registerAgent(
  sa: Address,
  name: string,
  signHash: SignHash,
): Promise<{ ok: true; txHash?: Hex; cardHash: string; bindingProofHash: string } | { ok: false; error: string }> {
  const issuedAt = new Date().toISOString();
  const card: AgentCard = { type: 'service', displayName: name };
  const cardHash = hashAgentCard(card);
  if (!DISCOVERY_REGISTRY_ID) return { ok: false, error: 'This Home has no directory configured, so there is nowhere to register. (NEXT_PUBLIC_AGENT_REGISTRY_URN)' };
  const registryId = DISCOVERY_REGISTRY_ID as RegistryId;
  const entryId = `urn:ap:registry-entry:${name}` as RegistryEntryId;
  // NEW-RK-1: chainId + registryAddress domain-scope the binding proof (BindingProofBody requires them).
  const bindingProofHash = await hashBindingProofBody({ registryId, entryId, subjectAgent: sa, cardHash, claimHashes: [], issuedAt, chainId: CHAIN_ID, registryAddress: CONTRACTS.agentRegistryBase });
  const call = buildRegisterEntryCall({
    registry: CONTRACTS.agentRegistryBase, registryId, entryId, subjectAgent: sa,
    cardHash, bindingProofHash, claimHashes: [], expiresAt: 0,
  });
  // The SA executes registerEntry itself (execute(target,value,data)) — so msg.sender == subjectAgent.
  const executeData = encodeFunctionData({ abi: PAY_EXECUTE_ABI, functionName: 'execute', args: [call.to, 0n, call.data] });
  const res = await executeCall(sa, signHash, executeData);
  if (!res.ok) return res;
  requestReindex([sa]); // auto-index: re-project so the `registry` facet flips to registered in discovery
  return { ok: true, txHash: res.txHash, cardHash, bindingProofHash };
}

/** Publish the connection-bootstrap record (spec 280) for a name the caller stewards — the OPT-IN,
 *  owner-authorized, PUBLIC `name → how-to-connect` association. The agent's OWN SA writes its resolver
 *  attributes (`_requireAuth → msg.sender == registry.owner(node)` = the SA), signed by `signHash` (the
 *  same root credential) + sponsored, gasless via `executeCall` — ONE prompt. `connectionKind` is always
 *  set; `connectionAddress` (the EOA / C_sub pre-select hint) is written ONLY when the caller explicitly
 *  passes it (the public-address opt-in). Never call this automatically — it is a deliberate UI action. */
export async function setConnectionInfo(
  sa: Address,
  name: string,
  kind: ConnectionKind,
  signHash: SignHash,
  opts: { address?: Address } = {},
): Promise<{ ok: true; txHash?: Hex } | { ok: false; error: string }> {
  const node = namehash(name);
  const resolver = CONTRACTS.agentNameResolver;
  const calls: ContractCall[] = [
    buildSetBytes32AttributeCall({ resolver, node, predicate: PREDICATE_ID.connectionKind, value: CONNECTION_KIND_ID[kind] }),
  ];
  if (opts.address) {
    calls.push(buildSetAddressAttributeCall({ resolver, node, predicate: PREDICATE_ID.connectionAddress, value: opts.address }));
  }
  const res = await executeCall(sa, signHash, buildExecuteBatchCallData(calls));
  if (!res.ok) return res;
  return { ok: true, txHash: res.txHash };
}

// ── Publish for discovery — the agent's OWN SA writes its `atl:capabilities` profile property ──────
/** LEGACY rail (ADR-0051). Read only, and only while `atl:capabilities` is empty. */
const ATL_SKILLS: Hex = keccak256(toBytes('atl:skills'));
/** The current rail: comma-joined capability ids. Mirrors AgentProfilePredicates.ATL_CAPABILITIES. */
const ATL_CAPABILITIES: Hex = keccak256(toBytes('atl:capabilities'));

async function readProfileString(sa: Address, predicate: Hex): Promise<string> {
  const pc = createPublicClient({ chain: CHAIN, transport: http(DEFAULT_RPC_URL) });
  return (await pc.readContract({
    address: CONTRACTS.agentProfileResolver, abi: agentProfileResolverAbi,
    functionName: 'getStringProperty', args: [sa, predicate],
  })) as string;
}

/**
 * The capability ids this agent publishes for discovery.
 *
 * ONE mechanism with a DOCUMENTED MIGRATION, not a fallback (ADR-0013). `atl:capabilities` is the rail;
 * `atl:skills` is the same rail under its old name, and an agent that has not published since the rename
 * still has its ids there. "New empty, old populated" is precisely the migration state — the question
 * being asked is unchanged and only the storage key moved. It is NOT "try the good source, then a
 * weaker one": both hold the same kind of value, written by the same owner, on the same contract.
 *
 * Writes only ever go to the new predicate, so an agent leaves this state the first time it publishes.
 */
export async function readAdvertisedCapabilityIds(sa: Address): Promise<string[]> {
  const split = (v: string): string[] => (v ? v.split(',').map((x) => x.trim()).filter(Boolean) : []);
  try {
    const current = split(await readProfileString(sa, ATL_CAPABILITIES));
    if (current.length > 0) return current;
    return split(await readProfileString(sa, ATL_SKILLS));
  } catch { return []; }
}

/** @deprecated Renamed `readAdvertisedCapabilityIds` (ADR-0051). */
export const getSkills = readAdvertisedCapabilityIds;
export const getCapabilities = readAdvertisedCapabilityIds;

/** Publish capabilities for discovery (spec 282): the agent's own SA writes `atl:skills` on AgentProfileResolver
 *  (`onlyAgent` → msg.sender == SA via executeCall), signed by `signHash`, gasless. `setStringProperty`
 *  is `onlyRegistered`, so we first `register` the profile in the SAME batch if needed (register reverts
 *  if already registered — AlreadyRegistered — hence the isRegistered gate). The published labels are what
 *  the discovery indexer projects + the matcher ranks on; the agent's full PRIVATE claim set stays in its
 *  vault (Phase 2b). Fires the discovery re-index. */
/** Broadcast a batch of contract calls as ONE userOp on `sa` (spec 283/284 connect-treasury BIND step).
 *  Thin exported wrapper over the internal executeCall — lets the ceremony broadcast arbitrary
 *  ContractCalls (e.g. a2aEndpoint/mcpEndpoint naming-record writes) without re-implementing build→sign→
 *  submit. Empty calls is a no-op success. */
export async function executeCalls(
  sa: Address,
  signHash: SignHash,
  calls: ContractCall[],
): Promise<{ ok: true; txHash?: Hex } | { ok: false; error: string }> {
  if (calls.length === 0) return { ok: true };
  return executeCall(sa, signHash, buildExecuteBatchCallData(calls));
}

// ─── Spec 410 §1.2 — the ROTATION ceremony's chain primitives ───────────────────────────────────────────────
// Rotation = add the new credential → retire the old → re-approve every standing approved-digest wire under the new
// custody epoch, in ONE userOp signed by the OLD credential as its last act. The batch's order is the SDK's
// (`buildRotationBatch`), the key derivation is the account's (`approveDigest`), and this estate must run contracts
// generation 3 — an older estate has no `approveDigest`, and pretending with a computed future-epoch key is the
// exact hole generation 3 closes (THESIS-1a). Governed accounts (custody mode > 0) rotate through the custody
// policy's `RotateCredential` action under quorum, which is not this ceremony.

/** Register a NEW passkey on this device and return it as the credential the rotation adds. Overwrites this
 *  device's stored passkey (as `registerPasskey` always has) — the caller keeps the old one to restore on failure. */
export async function registerPasskeyCredentialRef(label: string): Promise<{ ref: Extract<CredentialRef, { kind: 'passkey' }>; passkey: DemoPasskey }> {
  const pk = await registerPasskey(label);
  const rpIdHash = await derivePasskeyRpIdHash();
  return { ref: { kind: 'passkey', credentialIdDigest: pk.credentialIdDigest, x: pk.pubKeyX, y: pk.pubKeyY, rpIdHash }, passkey: pk };
}

/** The account's custody mode from the canonical CustodyPolicy (0 = self-governing person; 1–3 governed). */
export async function readCustodyMode(personAgent: Address): Promise<number> {
  const pc = createPublicClient({ chain: CHAIN, transport: http('/a2a/rpc') });
  const cp = CONTRACTS.custodyPolicy;
  if (!cp || /^0x0{40}$/.test(cp)) return 0;
  try {
    return Number(await pc.readContract({ address: cp, abi: [{ type: 'function', name: 'custodyMode', stateMutability: 'view', inputs: [{ name: 'account', type: 'address' }], outputs: [{ type: 'uint8' }] }] as const, functionName: 'custodyMode', args: [personAgent] }));
  } catch { return 0; }
}

/** Whether THIS estate can perform the rotation ceremony at all, and why not when it cannot. */
export function rotationAvailability(): { ok: true } | { ok: false; reason: string } {
  if (CONTRACTS_GENERATION !== 3) return { ok: false, reason: `rotation is not available on this estate yet — its contracts are generation ${CONTRACTS_GENERATION}, and the ceremony needs generation 3 (spec 410 §1)` };
  return { ok: true };
}

/** ONE userOp: add → retire → approveDigest × N, signed by the OLD credential (`signHash`). */
export async function rotateCredential(
  personAgent: Address,
  signHash: SignHash,
  input: { add: CredentialRef; retire: { kind: 'custodian'; address: Address } | { kind: 'passkey'; credentialIdDigest: Hex }; reapprove: readonly Hex[];
    /** Wires the person STRUCK from the reviewed list: revoked on chain in the same batch, so the strike is said
     *  where every verifier reads it, not only implied by the missing re-approval. */
    revoke?: readonly DelegationWire[] },
): Promise<{ ok: true; txHash?: Hex } | { ok: false; error: string }> {
  const avail = rotationAvailability();
  if (!avail.ok) return { ok: false, error: avail.reason };
  let calls: ContractCall[];
  try {
    calls = buildRotationBatch({ scheme: { generation: 3, account: personAgent }, add: input.add, retire: input.retire, reapprove: input.reapprove });
    for (const w of input.revoke ?? []) {
      const d: Delegation = { delegator: w.delegator, delegate: w.delegate, authority: w.authority, caveats: w.caveats.map((c) => ({ enforcer: c.enforcer, terms: c.terms, args: (c.args ?? '0x') as Hex })), salt: BigInt(String(w.salt)), signature: w.signature };
      calls.push(buildRevokeDelegationCall(d, CONTRACTS.delegationManager));
    }
  } catch (e) { return { ok: false, error: e instanceof Error ? e.message : String(e) }; }
  return executeCall(personAgent, signHash, buildExecuteBatchCallData(calls), { attempts: 5 });
}

export async function setCapabilities(
  sa: Address,
  name: string,
  capabilityIds: string[],
  signHash: SignHash,
  opts: { displayName?: string } = {},
): Promise<{ ok: true; txHash?: Hex } | { ok: false; error: string }> {
  const resolver = CONTRACTS.agentProfileResolver;
  const value = capabilityIds.map((s) => s.trim()).filter(Boolean).join(', ');
  const calls: ContractCall[] = [];
  // onlyRegistered gate — register the profile first (in-batch) if the SA has no profile yet.
  let registered = false;
  try {
    const pc = createPublicClient({ chain: CHAIN, transport: http(DEFAULT_RPC_URL) });
    registered = (await pc.readContract({ address: resolver, abi: agentProfileResolverAbi, functionName: 'isRegistered', args: [sa] })) as boolean;
  } catch { /* default to not-registered → include register (safe: a never-registered SA needs it) */ }
  if (!registered) {
    calls.push(buildRegisterProfileCall({ profileResolver: resolver, agent: sa, displayName: opts.displayName ?? (name.split('.')[0] ?? '') }));
  }
  // Writes go to the NEW predicate only. Never dual-write: two rails holding the same fact is how they
  // drift, and the reader already handles an agent that has not moved yet.
  calls.push({ to: resolver, value: 0n, data: encodeFunctionData({ abi: agentProfileResolverAbi, functionName: 'setStringProperty', args: [sa, ATL_CAPABILITIES, value] }) });
  const res = await executeCall(sa, signHash, buildExecuteBatchCallData(calls));
  if (!res.ok) return res;
  requestReindex([sa]); // auto-index: project the published ids so the matcher ranks on them
  return { ok: true, txHash: res.txHash };
}

/** @deprecated Renamed `setCapabilities` (ADR-0051). */
export const setSkills = setCapabilities;

// ── Private skill-claim vault (spec 282 Phase 2b) — the PRIVATE tier ──────────────────────────────
// The person's CAPABILITY RECORD — capability claim credentials living in their Connect-home vault (KV,
// session-authorized) — never public. Each entry has an `asserted` flag; that subset's labels are what
// `setSkills` publishes for discovery. `SkillClaim` / `asserted` are legacy names (ADR-0051 prose/key split).
export interface CapabilityClaim {
  /** Human name. Kept as `label` because it is the record's wire key from before the rename. */
  label: string;
  skillId?: string;
  relation?: string;
  proficiency?: number;
  /** Published for discovery: this entry's id goes on chain and its content onto the A2A card. */
  asserted: boolean;
  createdAt?: number;
  /** Stable id — the SAME string that lands in `atl:capabilities`, ARD `capabilities[]` and card `skills[].id`. */
  capabilityId?: string;
  description?: string;
  tags?: string[];
  /** ARD representativeQueries. Only what the owner wrote — a projection must never invent these. */
  examples?: string[];
}

/** @deprecated Renamed `CapabilityClaim` (ADR-0051). */
export type SkillClaim = CapabilityClaim;

/** The id an entry publishes under: an explicit one, else a slug of its name. */
export function capabilityIdFor(c: Pick<CapabilityClaim, 'label' | 'capabilityId'>): string {
  const explicit = c.capabilityId?.trim();
  if (explicit) return explicit;
  return c.label.trim().toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 60);
}

/** The structured rows an owner has chosen to publish, in the shape the profile and card project. */
export function advertisedCapabilitiesFrom(claims: CapabilityClaim[]): AdvertisedCapabilityV1[] {
  return claims.filter((c) => c.asserted).map((c) => ({
    id: capabilityIdFor(c),
    name: c.label,
    description: c.description?.trim() || c.label,
    tags: c.tags?.filter(Boolean) ?? [],
    ...(c.examples?.length ? { examples: c.examples.filter(Boolean) } : {}),
  }));
}

/** Read the person's private capability record from the home vault (session token). */
export async function listSkillClaims(token: string): Promise<SkillClaim[]> {
  const r = await fetch('/connect/skills', { headers: { authorization: `Bearer ${token}` } });
  if (!r.ok) return [];
  const b = (await r.json().catch(() => ({}))) as { skills?: SkillClaim[] };
  return b.skills ?? [];
}

/** Persist the full private capability record to the home vault (session-authorized; no on-chain write). */
export async function saveSkillClaims(token: string, skills: SkillClaim[]): Promise<{ ok: true } | { ok: false; error: string }> {
  const r = await fetch('/connect/skills', {
    method: 'POST',
    headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
    body: JSON.stringify({ skills }),
  });
  const b = (await r.json().catch(() => ({}))) as { ok?: boolean; error?: string };
  return r.ok && b.ok ? { ok: true } : { ok: false, error: b.error ?? `save failed (HTTP ${r.status})` };
}

/** List ALL the connected person's organizations (private vault credentials), for the
 *  /you portal. Same-origin, authorized by the home session token (aud = the home aud).
 *
 *  spec 342 — filtered by lifecycle status HERE, at the read boundary, so a screen that never
 *  heard of the spec still hides deleted orgs. `surface` widens it: 'roster' adds inactive orgs
 *  (the organizations list, where they can be reactivated), 'any' filters nothing (a workspace
 *  page addressed by SA, and the Settings section itself). */
export async function listMyOrgs(token: string, surface: OrgSurface = 'working'): Promise<MyOrg[]> {
  const b = (await readRelatedOrgs(token).catch(() => ({}))) as { orgs?: MyOrg[] };
  return filterMyOrgsByLifecycle(b.orgs ?? [], surface);
}

export async function fetchSensitive(
  token: string,
): Promise<{ ok: true; email: string; phone: string } | { ok: false; reason: string }> {
  const r = await fetch('/me/sensitive', { headers: { authorization: `Bearer ${token}` } });
  const body = (await r.json()) as Record<string, unknown>;
  if (r.ok && body.sensitive) {
    const s = body.sensitive as { email: string; phone: string };
    return { ok: true, email: s.email, phone: s.phone };
  }
  return { ok: false, reason: (body.reason as string) ?? 'Sensitive details need a custody-grade sign-in.' };
}
