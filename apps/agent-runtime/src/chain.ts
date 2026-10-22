// The viem Chain demo-a2a signs for — derived from CHAIN_ID, never assumed.
//
// Every client used to be built with `chain: baseSepolia` while `transport` followed RPC_URL. Reads
// survive that (the chain object is only metadata to them), but every WRITE is signed with the chain
// object's id, so on anvil / a private chain the node rejected the raw tx with "Wrong chainId" — the
// local mode looked healthy right up to the first Smart Agent deploy.
import { defineChain, type Chain } from 'viem';
import { baseSepolia } from 'viem/chains';

const KNOWN: Record<number, Chain> = { [baseSepolia.id]: baseSepolia };

/** The private QBFT chains this runtime is deployed against (gcchain 28190/28191) seal a block every 1 s
 *  (faithchain `blockperiodseconds`; 2 s until 2026-10-22, set-block-period.sh). Told nothing, viem assumes 12 s
 *  and checks for a receipt only every 4 s, so every write waited up to two blocks longer than it took (measured
 *  2026-10-14: a 2-block userOp answered in 3.8–5.4 s). */
const PRIVATE_CHAIN_BLOCK_MS = 1_000;

/** How often to ask whether a transaction has landed: a quarter of a block (2026-10-21; it was half). On a 1 s chain
 *  that is 250 ms. Never faster than 250 ms: each ask is a read through the RPC gateway. */
export function receiptPollMs(env: { CHAIN_ID?: string; RPC_URL?: string }): number {
  const block = chainFor(env).blockTime ?? PRIVATE_CHAIN_BLOCK_MS;
  return Math.min(Math.max(Math.floor(block / 4), 250), 4_000);
}

/** Chain for `env.CHAIN_ID` (default Base Sepolia). Unknown ids get a minimal definition whose
 *  load-bearing fields are `id` and `blockTime`; `RPC_URL` is what the transport actually uses. */
export function chainFor(env: { CHAIN_ID?: string; RPC_URL?: string }): Chain {
  const id = Number(env.CHAIN_ID ?? baseSepolia.id);
  if (!Number.isInteger(id) || id <= 0) throw new Error(`CHAIN_ID is not a positive integer: ${env.CHAIN_ID}`);
  return (
    KNOWN[id] ??
    defineChain({
      id,
      name: `chain-${id}`,
      nativeCurrency: { name: 'Ether', symbol: 'ETH', decimals: 18 },
      rpcUrls: { default: { http: env.RPC_URL ? [env.RPC_URL] : [] } },
      blockTime: PRIVATE_CHAIN_BLOCK_MS,
    })
  );
}
