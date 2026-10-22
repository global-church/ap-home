import { describe, expect, it } from 'vitest';
import { ContractFunctionExecutionError, ContractFunctionRevertedError, encodeErrorResult } from 'viem';
import { entryPointAbi } from '@agenticprimitives/agent-account';

import { BatchingQueue, failedOpIndex, HANDLE_OPS_BASE_GAS, MAX_BATCH_GAS, PER_OP_OVERHEAD_GAS } from '../src/relay-queue-core.js';

/**
 * The relay queue's rules (GC, 2026-10-20): ops that arrive while a send is in flight go out together; a
 * batch of one is sent with no simulation; an op the EntryPoint would refuse is sent alone; a failed send
 * fails exactly the ops in it.
 */

const tick = () => new Promise<void>((r) => setTimeout(r, 0));

function harness(opts: { refuse?: Set<string>; failSend?: boolean; simulateThrows?: boolean } = {}) {
  const sends: string[][] = [];
  const simulations: string[][] = [];
  let release: (() => void) | null = null;
  const queue = new BatchingQueue<string, string>({
    gatherMs: 0,
    sleep: async () => {},
    simulate: async (ops) => {
      simulations.push([...ops]);
      if (opts.simulateThrows) throw new Error('rpc down');
      const i = ops.findIndex((op) => opts.refuse?.has(op));
      return i < 0 ? null : i;
    },
    send: async (ops) => {
      sends.push([...ops]);
      // The first send is held open until the test releases it, so later submissions queue behind it.
      if (sends.length === 1) await new Promise<void>((r) => (release = r));
      if (opts.failSend) throw new Error('send failed');
      return `tx${sends.length}`;
    },
  });
  return { queue, sends, simulations, release: () => release?.() };
}

describe('the relay queue', () => {
  it('a lone op is sent as before: no simulation, one transaction', async () => {
    const h = harness();
    const p = h.queue.submit('a');
    await tick();
    h.release();
    expect(await p).toBe('tx1');
    expect(h.sends).toEqual([['a']]);
    expect(h.simulations).toEqual([]);
  });

  it('ops arriving while a send is in flight go out together in the next transaction', async () => {
    const h = harness();
    const first = h.queue.submit('a');
    await tick();
    const rest = ['b', 'c', 'd'].map((op) => h.queue.submit(op));
    await tick();
    h.release();
    expect(await first).toBe('tx1');
    expect(await Promise.all(rest)).toEqual(['tx2', 'tx2', 'tx2']);
    expect(h.sends).toEqual([['a'], ['b', 'c', 'd']]);
  });

  it('an op the EntryPoint would refuse is sent alone, and the rest still go together', async () => {
    const h = harness({ refuse: new Set(['c']) });
    const first = h.queue.submit('a');
    await tick();
    const rest = ['b', 'c', 'd'].map((op) => h.queue.submit(op));
    await tick();
    h.release();
    await first;
    const results = await Promise.all(rest);
    expect(h.sends).toEqual([['a'], ['c'], ['b', 'd']]);
    expect(results).toEqual(['tx3', 'tx2', 'tx3']);
  });

  it('a simulation that cannot answer does not hold the batch', async () => {
    const h = harness({ simulateThrows: true });
    const first = h.queue.submit('a');
    await tick();
    const rest = ['b', 'c'].map((op) => h.queue.submit(op));
    await tick();
    h.release();
    await first;
    await Promise.all(rest);
    expect(h.sends).toEqual([['a'], ['b', 'c']]);
  });

  it('a failed send fails exactly the ops in it', async () => {
    const h = harness({ failSend: true });
    const p = h.queue.submit('a');
    await tick();
    h.release();
    await expect(p).rejects.toThrow('send failed');
  });

  it('never more than the batch limit in one transaction', async () => {
    const sends: number[] = [];
    const q = new BatchingQueue<number, number>({ gatherMs: 0, maxBatch: 4, sleep: async () => {}, simulate: async () => null, send: async (ops) => (sends.push(ops.length), ops.length) });
    await Promise.all(Array.from({ length: 10 }, (_, i) => q.submit(i)));
    expect(Math.max(...sends)).toBeLessThanOrEqual(4);
    expect(sends.reduce((a, b) => a + b, 0)).toBe(10);
  });
});

describe('failedOpIndex', () => {
  const revert = (errorName: 'FailedOp' | 'FailedOpWithRevert', args: readonly unknown[]) => {
    const data = encodeErrorResult({ abi: entryPointAbi, errorName, args } as never);
    const cause = new ContractFunctionRevertedError({ abi: entryPointAbi, data, functionName: 'handleOps' });
    return new ContractFunctionExecutionError(cause, { abi: entryPointAbi, functionName: 'handleOps', args: [] });
  };

  it('reads the op index from FailedOp and FailedOpWithRevert', () => {
    expect(failedOpIndex(revert('FailedOp', [2n, 'AA25 invalid account nonce']))).toBe(2);
    expect(failedOpIndex(revert('FailedOpWithRevert', [0n, 'AA23 reverted', '0x']))).toBe(0);
  });

  it('anything else is not an op failure', () => {
    expect(failedOpIndex(new Error('fetch failed'))).toBeNull();
    expect(failedOpIndex(undefined)).toBeNull();
  });
});

describe('the gas budget per transaction (2026-10-21)', () => {
  // Ten ~2M-gas account deploys made one ~21.1M-gas handleOps; the chain caps a transaction at 16,777,216 and
  // refused it, failing all ten hosts together.
  const DEPLOY = 2_000_000n;
  const txGas = (n: number) => HANDLE_OPS_BASE_GAS + BigInt(n) * (DEPLOY + PER_OP_OVERHEAD_GAS);

  it('ten deploys go out as transactions that each fit under the chain cap', async () => {
    const sends: number[][] = [];
    const q = new BatchingQueue<number, number>({
      gatherMs: 0, sleep: async () => {}, simulate: async () => null, gasOf: () => DEPLOY,
      send: async (ops) => (sends.push([...ops]), ops.length),
    });
    await Promise.all(Array.from({ length: 10 }, (_, i) => q.submit(i)));
    expect(sends.flat().sort((a, b) => a - b)).toEqual([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
    for (const batch of sends) expect(txGas(batch.length)).toBeLessThanOrEqual(MAX_BATCH_GAS);
    expect(MAX_BATCH_GAS).toBeLessThan(16_777_216n);
    expect(sends.length).toBeGreaterThan(1);
  });

  it('an op bigger than the budget still goes, alone', async () => {
    const sends: number[][] = [];
    const q = new BatchingQueue<number, number>({
      gatherMs: 0, sleep: async () => {}, simulate: async () => null, gasOf: (op) => (op === 0 ? 20_000_000n : DEPLOY),
      send: async (ops) => (sends.push([...ops]), 1),
    });
    await Promise.all([0, 1].map((i) => q.submit(i)));
    expect(sends[0]).toEqual([0]);
    expect(sends.flat().sort()).toEqual([0, 1]);
  });
});
