import { describe, expect, it } from 'vitest';
import { withPromptReceipts } from '../src/chain';

const HASH = ('0x' + 'ab'.repeat(32)) as `0x${string}`;

function fakeBundler(opts: { viemWait: () => Promise<unknown>; minedAfterPolls: number }) {
  let polls = 0;
  const publicClient = {
    waitForTransactionReceipt: (_args: unknown) => opts.viemWait(),
    getTransactionReceipt: async () => {
      polls++;
      if (polls < opts.minedAfterPolls) throw new Error('TransactionReceiptNotFoundError');
      return { transactionHash: HASH, status: 'success' };
    },
  };
  return { client: { publicClient }, polls: () => polls };
}

describe('a receipt wait that cannot sleep through an idle minute (2026-10-22)', () => {
  it('finds a mined transaction by asking directly, while viem waits for a block that is a minute away', async () => {
    const b = fakeBundler({ viemWait: () => new Promise(() => {}), minedAfterPolls: 3 });
    withPromptReceipts(b.client, 5);
    const t = Date.now();
    const r = await (b.client.publicClient.waitForTransactionReceipt as (a: unknown) => Promise<{ transactionHash: string }>)({ hash: HASH, pollingInterval: 5 });
    expect(r.transactionHash).toBe(HASH);
    expect(Date.now() - t).toBeLessThan(1_000);
  });

  it("keeps viem's answer when it comes first (a replaced transaction is still viem's to report)", async () => {
    const replacement = { transactionHash: '0xreplacement' };
    const b = fakeBundler({ viemWait: async () => replacement, minedAfterPolls: 1_000 });
    withPromptReceipts(b.client, 5);
    expect(await (b.client.publicClient.waitForTransactionReceipt as (a: unknown) => Promise<unknown>)({ hash: HASH })).toBe(replacement);
  });

  it("passes viem's failure through when nothing was found, and stops asking", async () => {
    const b = fakeBundler({ viemWait: async () => { throw new Error('WaitForTransactionReceiptTimeoutError'); }, minedAfterPolls: 1_000 });
    withPromptReceipts(b.client, 5);
    await expect((b.client.publicClient.waitForTransactionReceipt as (a: unknown) => Promise<unknown>)({ hash: HASH })).rejects.toThrow('Timeout');
    const after = b.polls();
    await new Promise((r) => setTimeout(r, 30));
    expect(b.polls()).toBeLessThanOrEqual(after + 1);
  });
});
