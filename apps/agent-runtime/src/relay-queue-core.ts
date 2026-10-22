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
// This file is the pure core (no Workers imports), tested in test/relay-queue.test.ts; relay-queue.ts is the
// Durable Object around it.

import { BaseError, ContractFunctionRevertedError } from 'viem';

/** Most userOps in one handleOps. */
export const MAX_BATCH = 16;
/**
 * The most gas one handleOps may carry (2026-10-21). The chain caps a single TRANSACTION's gas at 2^24 =
 * 16,777,216 (EIP-7825); a batch is one transaction, and the bundler sets its gas to the sum of the ops' own
 * limits plus overhead (agent-account bundler-client: Σ(verification + call + preVerification) + 150k per op +
 * 100k). Ten account deploys came to ~21.1M and the node refused the whole batch with "Transaction gas limit cap
 * exceeded" — which viem renders "Request exceeds defined limit" — so every host in it failed together. A batch now
 * stops before this budget; one op always goes, alone if it must (as before batching).
 */
export const MAX_BATCH_GAS = 16_000_000n;
/** The bundler's fixed overhead around the ops' own gas (bundler-client.js). */
export const HANDLE_OPS_BASE_GAS = 100_000n;
export const PER_OP_OVERHEAD_GAS = 150_000n;
/** When the queue was idle, how long the first op waits for company before the send starts. */
export const GATHER_MS = 50; // 300 until 2026-10-22: a burst batches anyway while a send is in flight; the idle wait was 0.25 s per write

interface Waiter<Op, R> {
  readonly op: Op;
  readonly resolve: (r: R) => void;
  readonly reject: (e: unknown) => void;
}

export interface BatchingDeps<Op, R> {
  /** Index of the first op the EntryPoint would refuse, or null when the batch would go through. Throws when
   *  it cannot tell (then the batch is sent as is). */
  simulate(ops: readonly Op[]): Promise<number | null>;
  send(ops: readonly Op[]): Promise<R>;
  gatherMs?: number;
  maxBatch?: number;
  /** An op's own gas as the bundler counts it (verification + call + preVerification). Absent = no gas budget. */
  gasOf?: (op: Op) => bigint;
  maxBatchGas?: bigint;
  sleep?: (ms: number) => Promise<void>;
  onBatch?: (info: { size: number; droppedToSingle: number }) => void;
}

/** One sender, batching. Every `submit` resolves with the receipt of the transaction that carried its op. */
export class BatchingQueue<Op, R> {
  private waiting: Waiter<Op, R>[] = [];
  private running = false;

  constructor(private readonly deps: BatchingDeps<Op, R>) {}

  submit(op: Op): Promise<R> {
    return new Promise<R>((resolve, reject) => {
      this.waiting.push({ op, resolve, reject });
      void this.run();
    });
  }

  /** Ops waiting for a send (for tests and logs). */
  get depth(): number {
    return this.waiting.length;
  }

  private async run(): Promise<void> {
    if (this.running) return;
    this.running = true;
    const sleep = this.deps.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
    try {
      // Idle → busy: give concurrent submitters a moment to arrive. After that, whatever arrived while a send
      // was in flight is the next batch, with no extra wait.
      const gather = this.deps.gatherMs ?? GATHER_MS;
      if (gather > 0) await sleep(gather);
      while (this.waiting.length > 0) {
        const batch = this.waiting.splice(0, this.batchSize());
        await this.dispatch(batch);
      }
    } finally {
      this.running = false;
      if (this.waiting.length > 0) void this.run();
    }
  }

  /** How many waiting ops the next batch takes: at most maxBatch, and no more than fit the gas budget (always ≥ 1). */
  private batchSize(): number {
    const max = Math.min(this.deps.maxBatch ?? MAX_BATCH, this.waiting.length);
    const gasOf = this.deps.gasOf;
    if (!gasOf) return max;
    const budget = this.deps.maxBatchGas ?? MAX_BATCH_GAS;
    let total = HANDLE_OPS_BASE_GAS;
    let n = 0;
    while (n < max) {
      const next = total + gasOf(this.waiting[n]!.op) + PER_OP_OVERHEAD_GAS;
      if (n > 0 && next > budget) break;
      total = next;
      n++;
    }
    return Math.max(1, n);
  }

  private async dispatch(batch: Waiter<Op, R>[]): Promise<void> {
    let rest = batch;
    let dropped = 0;
    // Several ops: find any the EntryPoint would refuse and send each of those alone, as it would have been sent
    // before batching existed. At most one simulation per op, so a pathological batch still finishes.
    while (rest.length > 1 && dropped < batch.length) {
      let failing: number | null;
      try {
        failing = await this.deps.simulate(rest.map((w) => w.op));
      } catch {
        break; // cannot tell: send as is
      }
      if (failing === null || failing < 0 || failing >= rest.length) break;
      const [bad] = rest.splice(failing, 1);
      dropped += 1;
      await this.sendGroup([bad as Waiter<Op, R>]);
    }
    this.deps.onBatch?.({ size: rest.length, droppedToSingle: dropped });
    if (rest.length > 0) await this.sendGroup(rest);
  }

  private async sendGroup(group: Waiter<Op, R>[]): Promise<void> {
    try {
      const receipt = await this.deps.send(group.map((w) => w.op));
      for (const w of group) w.resolve(receipt);
    } catch (e) {
      for (const w of group) w.reject(e);
    }
  }
}

/** The op index an EntryPoint FailedOp / FailedOpWithRevert revert names, or null when the error is not one. */
export function failedOpIndex(error: unknown): number | null {
  if (!(error instanceof BaseError)) return null;
  const reverted = error.walk((e) => e instanceof ContractFunctionRevertedError);
  if (!(reverted instanceof ContractFunctionRevertedError)) return null;
  const name = reverted.data?.errorName;
  if (name !== 'FailedOp' && name !== 'FailedOpWithRevert') return null;
  const index = reverted.data?.args?.[0];
  return typeof index === 'bigint' || typeof index === 'number' ? Number(index) : null;
}

