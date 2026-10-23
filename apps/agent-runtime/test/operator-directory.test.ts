import { describe, expect, it } from 'vitest';
import {
  appendAudit, canApprove, canDeny, canFetch, cleanEmail, EXPORT_APPROVAL_WINDOW_MS, EXPORT_FETCH_WINDOW_MS, exportStatus,
  exportSummary, maskEmail, newExportRequest, readContact, sessionProvesEmail, sha256Hex, type ExportRequest,
} from '../src/operator-directory';

const A = (n: number) => `0x${String(n).padStart(40, '0')}`;
const RYAN = A(1), PAUL = A(2), MALLORY = A(3);

describe('masking', () => {
  it('keeps enough to recognise and not enough to use', () => {
    expect(maskEmail('pastor@grace.org')).toBe('pa•••r@g•••.org');
    expect(maskEmail('a@b.co')).toBe('a•••@b•••.co');
    expect(maskEmail('pastor@grace.org')).not.toContain('pastor');
  });
  it('cleans what may be stored', () => {
    expect(cleanEmail('  Host@Church.ORG ')).toBe('host@church.org');
    expect(cleanEmail('nope')).toBeNull();
    expect(readContact({ v: 2, email: 'x@y.org', verifiedAt: 1, source: 's' })?.email).toBe('x@y.org');
    expect(readContact({ v: 1, iv: 'x', ct: 'y' })).toBeNull();
  });
});

describe('a session proves an email only when it signed in with that email', () => {
  it('custody-grade and login-grade email sessions', async () => {
    const h = await sha256Hex('host@church.org');
    expect(await sessionProvesEmail({ kind: 'oidc', id: `email#${h}` }, ' Host@Church.org ')).toBe(true);
    expect(await sessionProvesEmail({ kind: 'email', id: h }, 'host@church.org')).toBe(true);
  });
  it('another address, a Google or passkey session, or no principal: no', async () => {
    const h = await sha256Hex('host@church.org');
    expect(await sessionProvesEmail({ kind: 'oidc', id: `email#${h}` }, 'other@church.org')).toBe(false);
    expect(await sessionProvesEmail({ kind: 'oidc', id: `google#${h}` }, 'host@church.org')).toBe(false);
    expect(await sessionProvesEmail({ kind: 'passkey', id: h }, 'host@church.org')).toBe(false);
    expect(await sessionProvesEmail(undefined, 'host@church.org')).toBe(false);
  });
});

describe('two-admin export', () => {
  const t0 = 1_000_000;
  const req = newExportRequest({ id: 'e1', app: 'gather-app', accounts: [A(10), A(11).toUpperCase().replace('0X', '0x'), A(10), 'junk'], requestedBy: RYAN, now: t0 }) as ExportRequest;

  it('freezes a clean, de-duplicated account list', () => {
    expect(req.accounts).toEqual([A(10), A(11)]);
    expect(newExportRequest({ id: 'e2', app: 'gather-app', accounts: [], requestedBy: RYAN, now: t0 })).toEqual({ error: 'nothing to export' });
  });
  it('the requester cannot approve their own export; a different admin can', () => {
    expect(canApprove(req, RYAN, t0 + 1)).toEqual({ ok: false, reason: expect.stringContaining('second admin') });
    expect(canApprove(req, PAUL, t0 + 1)).toEqual({ ok: true });
  });
  it('nothing downloads before approval', () => {
    expect(canFetch(req, RYAN, t0 + 1)).toEqual({ ok: false, reason: expect.stringContaining('waiting') });
  });
  it('after approval only the requester downloads, once, inside the window', () => {
    const approved = { ...req, approvedBy: PAUL, approvedAt: t0 + 10 };
    expect(canFetch(approved, PAUL, t0 + 20)).toEqual({ ok: false, reason: expect.stringContaining('requested') });
    expect(canFetch(approved, MALLORY, t0 + 20).ok).toBe(false);
    expect(canFetch(approved, RYAN, t0 + 20)).toEqual({ ok: true });
    expect(canFetch({ ...approved, fetchedAt: t0 + 30 }, RYAN, t0 + 40)).toEqual({ ok: false, reason: 'this export is downloaded' });
    expect(canFetch(approved, RYAN, t0 + 10 + EXPORT_FETCH_WINDOW_MS + 1)).toEqual({ ok: false, reason: 'this export is expired' });
  });
  it('an unanswered request expires; a denied one stays denied', () => {
    expect(exportStatus(req, t0 + EXPORT_APPROVAL_WINDOW_MS + 1)).toBe('expired');
    expect(canApprove(req, PAUL, t0 + EXPORT_APPROVAL_WINDOW_MS + 1).ok).toBe(false);
    const denied = { ...req, deniedBy: PAUL, deniedAt: t0 + 5 };
    expect(canApprove(denied, PAUL, t0 + 6).ok).toBe(false);
    expect(canDeny(denied, t0 + 6).ok).toBe(false);
  });
  it('the request list shows a count, never the accounts', () => {
    const s = exportSummary(req, t0 + 1) as Record<string, unknown>;
    expect(s.count).toBe(2);
    expect(s.accounts).toBeUndefined();
    expect(s.status).toBe('pending');
  });
});

describe('audit log', () => {
  it('appends, lower-cases the actor, and stays bounded', () => {
    let log = appendAudit(null, { at: 1, by: RYAN.toUpperCase().replace('0X', '0x'), kind: 'reveal', account: A(10) });
    expect(log[0]!.by).toBe(RYAN);
    for (let i = 0; i < 1200; i++) log = appendAudit(log, { at: i, by: PAUL, kind: 'list' });
    expect(log.length).toBe(1000);
  });
});
