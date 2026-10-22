// THE RELAY QUEUE (GC, 2026-10-20) — one sender for the relay account, batching userOps into shared handleOps.
//
// WHY. Every chain write on a GCID estate (a home created, an org deployed, a grant, a listing) is a userOp the
// runtime submits itself, one `handleOps([userOp])` transaction per submission, from ONE relay account. Each
// send picks its nonce from `pending`; concurrent sends collide, one is mined, the others are replaced and
// retried (agent-account bundler-client). Measured on the GC staging estate with the Gather publish load test:
// every transaction in the window came from that one sender, one per block, about five a minute; a host needs
// about three, so publishing topped out near 100 an hour, with a multi-minute tail and an occasional
// "Couldn't finish … Try again". The chain was idle (blocks every 2 s on demand) and so were the VMs.
//
// WHAT. All submissions go to ONE Durable Object. While a send is in flight, new userOps wait; the next send
// carries all of them in one `handleOps(ops)` (the package already accepts a batch, and its receipt check
// already handles several senders in one receipt). Only this object sends from the relay account on the userOp
// path, so the nonce collisions stop.
//
// SAFETY.
//  - A batch of ONE is sent exactly as before: no simulation, the same call.
//  - A batch of several is first simulated (eth_call of handleOps). If the EntryPoint names a failing op
//    (FailedOp / FailedOpWithRevert, which carry its index), that op is sent ALONE — so it fails the way it
//    would have failed before, with its own reverted receipt — and the rest go together. A simulation that
//    cannot answer (RPC trouble) does not hold anything up: the batch is sent as is.
//  - A send that throws rejects every op in it with that error, as the single send did: no blind resend that
//    could report a failure for an op that was in fact mined.
//  - Behind RELAY_QUEUE=on. Off (the default), nothing here runs and submissions are exactly as before.
//
// Pure core (`BatchingQueue`) + the Durable Object around it, so the batching rules are tested without a chain.

import { DurableObject } from 'cloudflare:workers';
import { createPublicClient, http, type Address, type LocalAccount, type TransactionReceipt } from 'viem';
import { BundlerClient, entryPointAbi, unpackGasLimits, type PackedUserOperation } from '@agenticprimitives/agent-account';

import { chainFor, receiptPollMs } from './chain.js';
import { BatchingQueue, failedOpIndex } from './relay-queue-core.js';
import { getRelayerAccount, type RelayerEnv } from './relayer.js';

export interface RelayQueueEnv extends RelayerEnv {
  RPC_URL?: string;
  CHAIN_ID?: string;
  ENTRY_POINT?: string;
}

/**
 * The Durable Object: one instance (`idFromName('relay')`) per estate. `submit` is what the runtime's
 * `submitDeployUserOp` / `submitCallUserOp` call when RELAY_QUEUE=on.
 */
export class RelayQueueDO extends DurableObject<RelayQueueEnv> {
  /** Set by index.ts at load: the runtime's audit sink factory (it lives there, beside the rest of the env). */
  static auditSinkFor: ((env: RelayQueueEnv) => Parameters<typeof getRelayerAccount>[2]) | null = null;

  private account: Promise<LocalAccount> | null = null;
  private readonly queue = new BatchingQueue<PackedUserOperation, TransactionReceipt>({
    simulate: (ops) => this.simulate(ops),
    send: (ops) => this.send(ops),
    // The gas budget per handleOps (relay-queue-core MAX_BATCH_GAS): counted the way the bundler counts it.
    gasOf: (op) => {
      const { high, low } = unpackGasLimits(op.accountGasLimits);
      return high + low + BigInt(op.preVerificationGas);
    },
    onBatch: ({ size, droppedToSingle }) => {
      if (size > 1 || droppedToSingle > 0) console.log(`[relay-queue] handleOps with ${size} userOp(s)${droppedToSingle ? `, ${droppedToSingle} sent alone after simulation` : ''}`);
    },
  });

  private relayAccount(): Promise<LocalAccount> {
    if (!this.account) {
      const sink = RelayQueueDO.auditSinkFor?.(this.env);
      if (!sink) throw new Error('[relay-queue] audit sink not wired (index.ts sets RelayQueueDO.auditSinkFor)');
      this.account = getRelayerAccount(this.env, 'direct-deploy', sink).catch((e: unknown) => {
        this.account = null;
        throw e;
      });
    }
    return this.account;
  }

  private entryPoint(): Address {
    if (!this.env.ENTRY_POINT) throw new Error('[relay-queue] ENTRY_POINT unset');
    return this.env.ENTRY_POINT as Address;
  }

  private async simulate(ops: readonly PackedUserOperation[]): Promise<number | null> {
    const account = await this.relayAccount();
    const client = createPublicClient({ chain: chainFor(this.env), transport: http(this.env.RPC_URL) });
    try {
      await client.simulateContract({
        address: this.entryPoint(),
        abi: entryPointAbi,
        functionName: 'handleOps',
        args: [ops as PackedUserOperation[], account.address],
        account: account.address,
      });
      return null;
    } catch (e) {
      const index = failedOpIndex(e);
      if (index === null) throw e;
      return index;
    }
  }

  private async send(ops: readonly PackedUserOperation[]): Promise<TransactionReceipt> {
    const account = await this.relayAccount();
    const bundler = new BundlerClient({ rpcUrl: this.env.RPC_URL ?? '', entryPoint: this.entryPoint(), pollingIntervalMs: receiptPollMs(this.env) });
    return (await bundler.sendUserOps([...ops], account.address, account)) as TransactionReceipt;
  }

  /** One userOp in; the receipt of the transaction that carried it out. */
  async submit(op: PackedUserOperation): Promise<TransactionReceipt> {
    return this.queue.submit(op);
  }
}
