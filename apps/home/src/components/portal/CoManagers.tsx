'use client';
// CO-MANAGERS (2026-10-23; server: server/connect/co-manager.ts). On an organization's page, someone who manages it can
// offer another person co-management: they sign a stewardship grant AS THE ORG, the person accepts while signed in as
// themselves, and from then on they manage it too (and, for the operator org, are an admin). Optionally the accepted
// person's custodian is added to the org's account, so either of them can act as the org: losing one account no longer
// locks everyone out. The offer-side card is <CoManagers>; the person's side is <CoManagerOffers>.
import { useCallback, useEffect, useState } from 'react';
import { encodeFunctionData } from 'viem';
import type { Address } from '@agenticprimitives/types';
import { Button, ErrorNote, Meta, Mono, Note, Section } from '../../ui';
import type { Session } from '../../context/session';
import { cachedConnectionCustodian, executeCalls, fetchProfile, resolveGoogleCustodian } from '../../connect-client';
import { resolveVia, signHashFor } from '../../home/onboarding';
import { issueSiteDelegation } from '../../lib/delegation';

const short = (a: string) => `${a.slice(0, 6)}…${a.slice(-4)}`;
const ADD_CUSTODIAN_ABI = [
  { type: 'function', name: 'addCustodian', stateMutability: 'nonpayable', inputs: [{ name: 'owner', type: 'address' }], outputs: [] },
] as const;

interface OfferRow { org: string; person: string; orgName: string; offeredBy: string; offeredAt: number; acceptedAt?: number; custodian?: string; custodianAdded?: boolean }

async function asOrg(session: Session, org: string) {
  const profile = await fetchProfile(session.token);
  return signHashFor(resolveVia(profile?.credential, session.via), org as Address, { token: session.token });
}

/** For someone who manages `org`: offer co-management, see the offers, add an accepted person as co-custodian. */
export function CoManagers({ org, session }: { org: string; session: Session }) {
  const [person, setPerson] = useState('');
  const [offers, setOffers] = useState<OfferRow[]>([]);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);

  const load = useCallback(async () => {
    const r = await fetch(`/connect/co-manager?org=${org.toLowerCase()}`, { headers: { authorization: `Bearer ${session.token}` } }).catch(() => null);
    const j = (await r?.json().catch(() => null)) as { offers?: OfferRow[] } | null;
    if (r?.ok) setOffers(j?.offers ?? []);
  }, [org, session.token]);
  useEffect(() => { void load(); }, [load]);

  const run = async (fn: () => Promise<void>) => {
    setBusy(true); setErr(null); setMsg(null);
    try { await fn(); } catch (e) { setErr(e instanceof Error ? e.message : String(e)); } finally { setBusy(false); }
  };

  const offer = () => run(async () => {
    const p = person.trim().toLowerCase();
    if (!/^0x[0-9a-f]{40}$/.test(p)) throw new Error('Enter the person’s GCID account address (0x…).');
    const sign = await asOrg(session, org);
    const d = await issueSiteDelegation(org as Address, p as Address, sign);
    const r = await fetch('/connect/co-manager', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${session.token}` },
      body: JSON.stringify({ action: 'offer', org, person: p, delegation: { ...d, salt: d.salt.toString() } }),
    });
    const j = (await r.json().catch(() => ({}))) as { error?: string };
    if (!r.ok) throw new Error(j.error ?? `offer failed (${r.status})`);
    setPerson('');
    setMsg('Offered. They accept from Stewardship → Organizations while signed in as themselves.');
    await load();
  });

  const addCustodian = (o: OfferRow) => run(async () => {
    const sign = await asOrg(session, org);
    const data = encodeFunctionData({ abi: ADD_CUSTODIAN_ABI, functionName: 'addCustodian', args: [o.custodian as Address] });
    const res = await executeCalls(org as Address, sign, [{ to: org as Address, value: 0n, data }]);
    if (!res.ok) throw new Error(res.error);
    setMsg(`${short(o.person)} can now act as this organization too.`);
    await load();
  });

  return (
    <Section title="Co-managers" testId="org-co-managers">
      <div style={{ display: 'flex', gap: '.5rem', flexWrap: 'wrap', alignItems: 'center' }}>
        <input
          style={{ flex: '1 1 260px', minWidth: 0, padding: '.45rem .6rem', borderRadius: 8, border: '1px solid var(--color-border-strong)', font: 'inherit' }}
          placeholder="Their GCID account address (0x…)"
          value={person}
          onChange={(e) => setPerson(e.target.value)}
          data-testid="co-manager-person"
        />
        <Button size="sm" onClick={() => void offer()} disabled={busy || !person.trim()} data-testid="co-manager-offer">{busy ? 'Working…' : 'Offer co-management'}</Button>
      </div>
      {err && <ErrorNote>{err}</ErrorNote>}
      {msg && <Note>{msg}</Note>}
      {offers.length > 0 && (
        <ul style={{ listStyle: 'none', padding: 0, margin: '.75rem 0 0' }}>
          {offers.map((o) => (
            <li key={o.person} style={{ padding: '.4rem 0', borderTop: '1px solid var(--color-border)' }}>
              <Mono title={o.person}>{short(o.person)}</Mono>{' '}
              <Meta>{!o.acceptedAt ? 'offered, not yet accepted' : o.custodianAdded ? 'co-manager and co-custodian' : 'co-manager'}</Meta>
              {o.acceptedAt && o.custodian && !o.custodianAdded && (
                <> <Button size="sm" onClick={() => void addCustodian(o)} disabled={busy} data-testid="co-manager-add-custodian">Add as co-custodian</Button></>
              )}
            </li>
          ))}
        </ul>
      )}
      <Note>A co-manager can do everything you can for this organization. A co-custodian can also act as the organization itself, so it is not locked out if one account is lost. Remove either by revoking their grant on the Grants page.</Note>
    </Section>
  );
}

/** For the signed-in person: organizations offering them co-management. */
export function CoManagerOffers({ session }: { session: Session }) {
  const [offers, setOffers] = useState<OfferRow[]>([]);
  const [busy, setBusy] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const load = useCallback(async () => {
    const r = await fetch('/connect/co-manager', { headers: { authorization: `Bearer ${session.token}` } }).catch(() => null);
    const j = (await r?.json().catch(() => null)) as { offers?: OfferRow[] } | null;
    if (r?.ok) setOffers(j?.offers ?? []);
  }, [session.token]);
  useEffect(() => { void load(); }, [load]);
  if (!offers.length) return null;

  const accept = async (o: OfferRow) => {
    setBusy(o.org); setErr(null);
    try {
      const profile = await fetchProfile(session.token);
      const me = (profile?.agent?.split(':').pop() ?? '') as Address;
      // The custodian that controls YOUR account (the server checks it on-chain), so the org can add it as co-custodian.
      const custodian = (await resolveGoogleCustodian(session.token).catch(() => null)) ?? (me ? cachedConnectionCustodian(me) : null);
      const r = await fetch('/connect/co-manager', {
        method: 'POST',
        headers: { 'content-type': 'application/json', authorization: `Bearer ${session.token}` },
        body: JSON.stringify({ action: 'accept', org: o.org, ...(custodian ? { custodian } : {}) }),
      });
      const j = (await r.json().catch(() => ({}))) as { error?: string };
      if (!r.ok) throw new Error(j.error ?? `accept failed (${r.status})`);
      await load();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  };

  return (
    <Section title="Co-management offers" testId="co-manager-offers">
      {offers.map((o) => (
        <div key={o.org} style={{ display: 'flex', gap: '.6rem', alignItems: 'center', flexWrap: 'wrap', padding: '.3rem 0' }}>
          <span><strong>{o.orgName}</strong> <Meta>offered by {short(o.offeredBy)}</Meta></span>
          <Button size="sm" onClick={() => void accept(o)} disabled={busy === o.org} data-testid="co-manager-accept">{busy === o.org ? 'Accepting…' : 'Accept'}</Button>
        </div>
      ))}
      {err && <ErrorNote>{err}</ErrorNote>}
    </Section>
  );
}
