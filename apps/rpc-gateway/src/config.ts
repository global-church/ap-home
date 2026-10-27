// Copied as-is from the live gateway (allow-list + cache TTLs). Behaviour-bearing constants — change
// with a test.
export const READ_METHODS = new Set(['eth_chainId','net_version','web3_clientVersion','eth_blockNumber','eth_gasPrice','eth_maxPriorityFeePerGas','eth_feeHistory','eth_getBalance','eth_getCode','eth_getStorageAt','eth_getTransactionCount','eth_call','eth_estimateGas','eth_getLogs','eth_getBlockByNumber','eth_getBlockByHash','eth_getTransactionByHash','eth_getTransactionReceipt','eth_getBlockReceipts']);
export const WRITE_METHODS = new Set(['eth_sendRawTransaction']);
export const isAllowed = (m: string) => READ_METHODS.has(m) || WRITE_METHODS.has(m);
export const isWrite = (m: string) => WRITE_METHODS.has(m);
export const CACHE_TTL_S = (method: string, params: unknown[]): number => {
  if (method === 'eth_chainId' || method === 'net_version' || method === 'web3_clientVersion') return 3600;
  const tag = typeof params?.[params.length - 1] === 'string' ? String(params[params.length - 1]) : '';
  if (tag === 'pending') return 0;
  const byKey = /^0x[0-9a-fA-F]+$/.test(tag) || method === 'eth_getBlockByHash' || method === 'eth_getTransactionReceipt';
  if (['eth_getLogs','eth_call','eth_getBlockByNumber','eth_getBalance','eth_getTransactionReceipt','eth_getBlockByHash','eth_getCode'].includes(method)) return byKey ? 30 : 2;
  return 0;
};

export type Rpc = { jsonrpc: string; id: unknown; method: string; params?: unknown[] };

/**
 * THE BROWSER SCOPE (2026-10-27). A token baked into a website bundle is public: anyone who views the
 * page source has it. Such a token is issued with `scope: 'browser'`, and this decides what it may do. The rule: a
 * browser may read what it can already name (a name it knows, an account it knows, its own transaction), never LIST
 * what the chain holds. The website needs only single reads (eth_call, eth_blockNumber, code, balance, receipts of
 * its own transactions), so nothing here is lost to it.
 *
 * Refused for a browser token:
 *  - logs and block receipts (every event: grants, revocations, name registrations);
 *  - raw storage reads (a registry's child list is readable slot by slot);
 *  - an eth_call with no `to`, or with a state override: both run caller-supplied code, which can call anything;
 *  - an eth_call whose data contains a LISTING function's selector anywhere: ABI-encoded calldata carries an inner
 *    call's bytes intact, so a listing reached through an account's execute() (eth_call needs no signature for
 *    `from`) is caught too. A false match is a 4-byte coincidence in a caller's own calldata.
 * Block reads are allowed but answered WITHOUT their transaction lists (see stripBlockTransactions), so a block
 * cannot be walked into every transaction's input.
 */
export const BROWSER_DENIED_METHODS = new Set(['eth_getLogs', 'eth_getBlockReceipts', 'eth_getStorageAt', 'eth_newFilter', 'eth_getFilterLogs', 'eth_getFilterChanges']);
/** Functions that return what the chain holds rather than a fact about something the caller names. Public vocabulary
 *  registries (ontology terms, relationship types, skills, name roots) stay readable. */
export const BROWSER_DENIED_SELECTORS: Readonly<Record<string, string>> = {
  '3002c03b': 'AgentNameRegistry.childLabelhashes(bytes32)',
  '981a3137': 'AgentNameRegistry.childCount(bytes32)',
  '860e4ac6': 'AgentProfileResolver.getAllAgents()',
  'b7dc1284': 'AgentProfileResolver.agentCount()',
  'c3a6123d': 'AttributeStorage.allSubjects()',
  '639a2e10': 'AttributeStorage.subjectCount()',
  'b392f0ae': 'GeoFeatureRegistry.allFeatures()',
};

/** Why a browser-scoped token may not make this call, or null when it may. */
export function browserRefusal(call: Rpc): string | null {
  if (BROWSER_DENIED_METHODS.has(call.method)) return `${call.method} is not available to a browser token`;
  if (call.method === 'eth_call' || call.method === 'eth_estimateGas') {
    const params = Array.isArray(call.params) ? call.params : [];
    const tx = (params[0] ?? {}) as { to?: unknown; data?: unknown; input?: unknown };
    if (typeof tx.to !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(tx.to)) return `${call.method} needs a contract address`;
    if (params.length > 2 && params[2] != null) return 'state overrides are not available to a browser token';
    const data = String(tx.data ?? tx.input ?? '').toLowerCase().replace(/^0x/, '');
    for (const [sel, name] of Object.entries(BROWSER_DENIED_SELECTORS)) if (data.includes(sel)) return `${name} lists the chain's contents and is not available to a browser token`;
  }
  return null;
}

/** A block answered to a browser token carries no transaction list (hashes or full transactions). */
export function stripBlockTransactions(method: string, result: unknown): unknown {
  if ((method === 'eth_getBlockByNumber' || method === 'eth_getBlockByHash') && result && typeof result === 'object' && 'transactions' in result) {
    return { ...(result as Record<string, unknown>), transactions: [] };
  }
  return result;
}

/**
 * Inject a `gas` bound into every `eth_estimateGas` call that does not set one. Some chains (Besu)
 * return an empty 200 without a bound on heavy calls and error when the bound equals the block gas
 * limit. `cap` comes from env `ESTIMATE_GAS_CAP`; empty/undefined = no-op (non-Besu chains). Mutates
 * in place (the batch is forwarded as-is) and returns the number of calls changed.
 */
export function injectEstimateGasCap(calls: Rpc[], cap: string | undefined): number {
  const c = (cap ?? '').trim();
  if (!c) return 0;
  if (!/^0x[0-9a-fA-F]+$/.test(c)) throw new Error(`ESTIMATE_GAS_CAP must be a hex quantity (got "${cap}")`);
  let n = 0;
  for (const call of calls) {
    const p0 = Array.isArray(call?.params) ? call.params[0] : undefined;
    if (call?.method === 'eth_estimateGas' && p0 && typeof p0 === 'object' && !(p0 as Record<string, unknown>).gas) {
      (p0 as Record<string, unknown>).gas = c;
      n++;
    }
  }
  return n;
}
