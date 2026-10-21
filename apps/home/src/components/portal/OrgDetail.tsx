'use client';
// Organization detail (spec 246/247) — everything the person's home knows about one org
// they govern, plus live reads over the two person↔org delegations:
//   • Stewardship (org→you)   → read the ORG's vault (its records).
//   • Membership  (you→org)   → read YOUR member record the org is entitled to see.
// All MCP access goes through demo-a2a; no data is copied into the home.
import { useCallback, useEffect, useState, type ReactNode } from 'react';
import { ExplorerLink } from '../shared/ExplorerLink';
import { decodeAbiParameters } from 'viem';
import type { Address } from '@agenticprimitives/types';
import { listMyReceivedDelegations, revokeGrantedDelegation, type MyOrg, type ReceivedDelegation } from '../../connect-client';
import { revokeRelationshipCredential } from '../../lib/org-membership';
import { useSession } from '../../context/session';
import { OrgArchetypeGrantsPanel } from './OrgArchetypeGrantsPanel';
import { resolveVia, signHashFor } from '../../home/onboarding';
import type { DelegationWire } from '../../lib/delegation';
import { CONTRACTS } from '../../lib/chain';
import { vaultListWithDelegation, vaultReadWithDelegation, vaultWriteWithDelegation, type VaultRecordRef } from '../../lib/vault-client';
import { AddressChip } from '../shared/AddressChip';
import { BuildingIcon, LinkIcon } from '../shared/Icons';

import { Loading } from '../shared/Loading';
import { orgTypeText, type OrgTypeV1 } from '../../lib/org-type';
/** The org's managed profile — the canonical "org details" record the steward edits.
 *  Stored in the ORG's own vault under `org:profile`, written over the stewardship
 *  delegation (delegator = org). Free-form, vertical-agnostic. */
const RT_ORG_PROFILE = 'org.profile'; // spec 322 W3 record-grammar rename (no migration — old records orphaned)
interface OrgProfile {
  v: 1;
  displayName?: string;
  description?: string;
  website?: string;
  contactEmail?: string;
  location?: string;
  /** Chosen when the organization was created (lib/org-type.ts). Shown here; not editable yet. */
  organizationType?: OrgTypeV1;
}

const ROOT_AUTHORITY = '0x0000000000000000000000000000000000000000000000000000000000000000';
const short = (h?: string) => (h && h.length > 14 ? `${h.slice(0, 8)}…${h.slice(-6)}` : h ?? '—');

function purposeLabel(p: string): string {
  if (p === 'jp-adopter-org') return 'Adopter org';
  if (p === 'jp-facilitator-org') return 'Facilitator org';
  return p.replace(/-/g, ' ');
}

/** Human-readable summary of a single caveat, decoded by matching the enforcer address. */
function caveatLabel(c: { enforcer: Address; terms: `0x${string}` }): string {
  const e = c.enforcer.toLowerCase();
  try {
    if (e === CONTRACTS.timestampEnforcer.toLowerCase()) {
      const [, validUntil] = decodeAbiParameters([{ type: 'uint256' }, { type: 'uint256' }], c.terms) as [bigint, bigint];
      return `Time-boxed — expires ${new Date(Number(validUntil) * 1000).toLocaleString()}`;
    }
    if (e === CONTRACTS.valueEnforcer.toLowerCase()) {
      const [v] = decodeAbiParameters([{ type: 'uint256' }], c.terms) as [bigint];
      return v === 0n ? 'No value transfer (0 wei)' : `Max value ${v.toString()} wei`;
    }
    if (e === CONTRACTS.allowedTargetsEnforcer.toLowerCase()) {
      const [t] = decodeAbiParameters([{ type: 'address[]' }], c.terms) as [Address[]];
      return `Allowed targets: ${t.length}`;
    }
  } catch {
    /* fall through to the generic label */
  }
  return `Enforcer ${short(c.enforcer)}`;
}

function Fact({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div style={{ display: 'flex', gap: '.6rem', padding: '.4rem 0', borderTop: '1px solid var(--c-g100, #eee)', fontSize: '.85rem' }}>
      <span style={{ color: 'var(--c-g500, #64748b)', minWidth: 130 }}>{label}</span>
      <span style={{ color: 'var(--c-g800, #1e293b)', wordBreak: 'break-word' }}>{children}</span>
    </div>
  );
}

export function DelegationCard({ kind, d }: { kind: 'App access' | 'Membership' | 'Stewardship'; d: DelegationWire }) {
  return (
    <div className="manage-card">
      <div className="manage-card-head">
        <span className="manage-card-label">{kind}</span>
        <span className="manage-card-badge live">{d.authority === ROOT_AUTHORITY ? 'root' : 'sub'}</span>
      </div>
      <Fact label="Delegator"><AddressChip address={d.delegator} size="sm" /></Fact>
      <Fact label="Delegate"><AddressChip address={d.delegate} size="sm" /></Fact>
      <Fact label="Caveats">
        {d.caveats.length === 0 ? 'none' : (
          <ul style={{ margin: 0, paddingLeft: '1rem' }}>
            {d.caveats.map((c, i) => <li key={i}>{caveatLabel(c)}</li>)}
          </ul>
        )}
      </Fact>
      <Fact label="Salt"><code>{short(BigInt(d.salt).toString(16))}</code></Fact>
      <Fact label="Signature"><code>{short(d.signature)}</code></Fact>
    </div>
  );
}

/** Live read over a delegation: list the delegator's vault records, expand each to JSON. */
export function VaultReader({ title, hint, delegation }: { title: string; hint: string; delegation: DelegationWire }) {
  const [records, setRecords] = useState<VaultRecordRef[] | null>(null);
  const [bodies, setBodies] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(true);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setBusy(true);
    setErr(null);
    vaultListWithDelegation(delegation)
      .then((r) => { if (!cancelled) setRecords(r); })
      .catch((e) => { if (!cancelled) setErr(e instanceof Error ? e.message : 'read failed'); })
      .finally(() => { if (!cancelled) setBusy(false); });
    return () => { cancelled = true; };
  }, [delegation]);

  async function show(rt: string) {
    if (bodies[rt]) return;
    try {
      const data = await vaultReadWithDelegation(delegation, rt);
      setBodies((b) => ({ ...b, [rt]: JSON.stringify(data, null, 2) }));
    } catch (e) {
      setBodies((b) => ({ ...b, [rt]: `(error: ${e instanceof Error ? e.message : 'read failed'})` }));
    }
  }

  return (
    <div className="dash-section" style={{ marginTop: '1.25rem' }}>
      <h3 className="subhead">{title}</h3>
      <p className="manage-card-blurb" style={{ margin: '0 0 .6rem' }}>{hint}</p>
      {busy ? (
        <p className="manage-card-blurb">Reading over the delegation…</p>
      ) : err ? (
        <p className="manage-card-blurb" style={{ color: 'var(--c-danger, #dc2626)' }}>Couldn&rsquo;t read: {err}</p>
      ) : !records || records.length === 0 ? (
        <p className="manage-card-blurb">No records yet.</p>
      ) : (
        <ul style={{ listStyle: 'none', margin: 0, padding: 0, fontSize: '.82rem' }}>
          {records.map((r) => (
            <li key={r.record_type} style={{ borderTop: '1px solid var(--c-g100, #eee)', padding: '.4rem 0' }}>
              <code>{r.record_type}</code>
              <span style={{ color: 'var(--c-g500, #64748b)' }}> · updated {r.updated_at}</span>{' '}
              <button
                type="button"
                onClick={() => void show(r.record_type)}
                style={{ background: 'none', border: 'none', color: 'var(--c-accent, #2563eb)', cursor: 'pointer', padding: 0, fontSize: '.8rem' }}
              >
                show
              </button>
              {bodies[r.record_type] && (
                <pre style={{ background: 'var(--c-g50, #f8fafc)', padding: '.45rem .6rem', borderRadius: 6, overflowX: 'auto', fontSize: '.72rem', margin: '.3rem 0 0' }}>
                  {bodies[r.record_type]}
                </pre>
              )}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

const FIELDS: Array<{ key: Exclude<keyof OrgProfile, 'v' | 'organizationType'>; label: string; ph: string; area?: boolean }> = [
  { key: 'displayName', label: 'Display name', ph: 'e.g. Grace Community Church' },
  { key: 'description', label: 'Description', ph: 'What this organization does', area: true },
  { key: 'website', label: 'Website', ph: 'https://…' },
  { key: 'contactEmail', label: 'Contact email', ph: 'hello@example.org' },
  { key: 'location', label: 'Location', ph: 'City, Country' },
];

const inputStyle: React.CSSProperties = {
  width: '100%', padding: '.5rem .6rem', borderRadius: 8, border: '1px solid var(--c-g200, #e2e8f0)',
  fontSize: '.85rem', fontFamily: 'inherit', background: '#fff',
};

/** Manage the org's own details over the STEWARDSHIP delegation (write to the org's vault).
 *  Read on mount, edit the fields, Save → vaultWriteWithDelegation(stewardship, org:profile). */
export function OrgProfileManager({ delegation }: { delegation: DelegationWire }) {
  const [p, setP] = useState<OrgProfile>({ v: 1 });
  const [busy, setBusy] = useState(true);
  const [saving, setSaving] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setBusy(true);
    setErr(null);
    vaultReadWithDelegation<OrgProfile>(delegation, RT_ORG_PROFILE)
      .then((r) => { if (!cancelled && r) setP({ ...r, v: 1 }); })
      .catch((e) => { if (!cancelled) setErr(e instanceof Error ? e.message : 'read failed'); })
      .finally(() => { if (!cancelled) setBusy(false); });
    return () => { cancelled = true; };
  }, [delegation]);

  async function save() {
    setSaving(true);
    setErr(null);
    setMsg(null);
    try {
      await vaultWriteWithDelegation(delegation, RT_ORG_PROFILE, p);
      setMsg('Saved to the organization’s vault ✓');
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'save failed');
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="dash-section" style={{ marginTop: '1.25rem' }}>
      <h3 className="subhead">Manage organization details</h3>
      <p className="manage-card-blurb" style={{ margin: '0 0 .7rem' }}>
        You have <b>stewardship</b> of this org, so you can edit its details. Changes are written to the
        <b> organization’s own vault</b> over your stewardship delegation — never copied into your home.
      </p>
      {busy ? (
        <Loading label="Loading the org’s details…" />
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '.6rem', maxWidth: 520 }}>
          {p.organizationType && (
            <div style={{ fontSize: '.8rem', color: 'var(--c-g600, #475569)' }} data-testid="org-type">
              Organization type: <b>{orgTypeText(p.organizationType)}</b>
            </div>
          )}
          {FIELDS.map((f) => (
            <label key={f.key} style={{ display: 'flex', flexDirection: 'column', gap: '.25rem', fontSize: '.8rem', color: 'var(--c-g600, #475569)' }}>
              {f.label}
              {f.area ? (
                <textarea
                  style={{ ...inputStyle, minHeight: 64, resize: 'vertical' }}
                  placeholder={f.ph}
                  value={p[f.key] ?? ''}
                  onChange={(e) => setP((s) => ({ ...s, [f.key]: e.target.value }))}
                />
              ) : (
                <input
                  style={inputStyle}
                  placeholder={f.ph}
                  value={p[f.key] ?? ''}
                  onChange={(e) => setP((s) => ({ ...s, [f.key]: e.target.value }))}
                />
              )}
            </label>
          ))}
          <div style={{ display: 'flex', gap: '.6rem', alignItems: 'center', marginTop: '.2rem' }}>
            <button type="button" className="btn-primary" style={{ fontSize: '.85rem', padding: '.45rem .9rem' }} onClick={() => void save()} disabled={saving}>
              {saving ? 'Saving…' : 'Save org details'}
            </button>
            {msg && <span style={{ fontSize: '.8rem', color: 'var(--c-success, #16a34a)' }}>{msg}</span>}
            {err && <span style={{ fontSize: '.8rem', color: 'var(--c-danger, #dc2626)' }}>{err}</span>}
          </div>
        </div>
      )}
    </div>
  );
}

/** One member of the org — an agent that delegated to it. The delegation's delegator IS the
 *  member, so we read the member's vault over it. `onRemove` = the steward's W3 removal. */
function MemberCard({ m, onRemove, removing }: { m: ReceivedDelegation; onRemove?: () => void; removing?: boolean }) {
  const d = m.delegation;
  const [open, setOpen] = useState(false);
  const [profile, setProfile] = useState<OrgProfile | null>(null);
  const [records, setRecords] = useState<VaultRecordRef[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function load() {
    setOpen(true);
    if (!d || records) return;
    setBusy(true);
    setErr(null);
    try {
      const [p, recs] = await Promise.all([
        vaultReadWithDelegation<OrgProfile>(d, RT_ORG_PROFILE),
        vaultListWithDelegation(d),
      ]);
      setProfile(p);
      setRecords(recs);
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'read failed');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="manage-card">
      <div className="manage-card-head">
        <span className="manage-card-label">{m.displayName || m.orgName || 'member'}</span>
        <span className="manage-card-badge live">Member</span>
        {onRemove && (
          <button type="button" className="btn-ghost" style={{ fontSize: '.72rem', padding: '.15rem .5rem', marginLeft: 'auto' }} disabled={removing} onClick={onRemove}>
            {removing ? 'Removing…' : 'Remove'}
          </button>
        )}
      </div>
      <div style={{ margin: '.45rem 0' }}><AddressChip address={m.orgAgent} size="sm" /></div>
      {!d ? (
        <p className="manage-card-blurb">No readable delegation for this member.</p>
      ) : !open ? (
        <button type="button" className="btn-ghost" style={{ fontSize: '.8rem', padding: '.3rem .6rem' }} onClick={() => void load()}>
          View member details →
        </button>
      ) : busy ? (
        <p className="manage-card-blurb">Reading {m.orgName || 'member'}&rsquo;s vault…</p>
      ) : err ? (
        <p className="manage-card-blurb" style={{ color: 'var(--c-danger, #dc2626)' }}>Couldn&rsquo;t read: {err}</p>
      ) : (
        <div style={{ fontSize: '.8rem' }}>
          {profile && (profile.displayName || profile.description || profile.website || profile.contactEmail || profile.location) ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '.2rem', marginBottom: '.4rem' }}>
              {profile.displayName && <div><b>{profile.displayName}</b></div>}
              {profile.description && <div style={{ color: 'var(--c-g600, #475569)' }}>{profile.description}</div>}
              {profile.website && <div style={{ color: 'var(--c-g500, #64748b)' }}>{profile.website}</div>}
              {profile.contactEmail && <div style={{ color: 'var(--c-g500, #64748b)' }}>{profile.contactEmail}</div>}
              {profile.location && <div style={{ color: 'var(--c-g500, #64748b)' }}>{profile.location}</div>}
            </div>
          ) : (
            <p className="manage-card-blurb">No profile set yet.</p>
          )}
          <div style={{ color: 'var(--c-g500, #64748b)', fontSize: '.72rem' }}>
            {records && records.length > 0 ? `Records: ${records.map((r) => r.record_type).join(', ')}` : 'No vault records.'}
          </div>
        </div>
      )}
    </div>
  );
}

/** Members of the org = agents holding a MEMBERSHIP DELEGATION to it (spec 321 — every join path
 *  mints one, and invited members may also hold the org's member-access grant). Channel/directory
 *  listings are a channels-surface concern and are deliberately NOT shown here (product decision
 *  2026-07-10). The steward can read each member's details over their delegation (spec 247) and
 *  remove a member (W3: listing + link + grant index removed; the org's member-access grant is
 *  revoked ON-CHAIN with the steward's credential). */
export function OrgMembers({ org, token }: { org: MyOrg; token: string | null }) {
  const { session, profile, agentAddress } = useSession();
  const [members, setMembers] = useState<ReceivedDelegation[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [removing, setRemoving] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const reload = useCallback(() => {
    if (!token) { setLoaded(true); return; }
    void listMyReceivedDelegations(token)
      .then((all) => setMembers(all.filter((r) => r.viaOrg.toLowerCase() === org.orgAgent.toLowerCase())))
      .catch(() => undefined)
      .then(() => setLoaded(true));
  }, [token, org.orgAgent]);
  useEffect(() => { reload(); }, [reload]);

  const remove = useCallback(async (member: string) => {
    if (!token || !session) return;
    if (!window.confirm('Remove this member? Their channel listing and membership records are removed, and the access grant the organization signed for them is revoked on-chain.')) return;
    setRemoving(member); setErr(null);
    try {
      const res = await fetch('/connect/org-member-remove', {
        method: 'POST',
        headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
        body: JSON.stringify({ org: org.orgAgent.toLowerCase(), member: member.toLowerCase() }),
      });
      const b = (await res.json().catch(() => ({}))) as { ok?: boolean; error?: string; memberAccessDelegation?: DelegationWire | null };
      if (!res.ok || !b.ok) throw new Error(b.error ?? `remove failed (${res.status})`);
      // W3 — on-chain revoke of the org→member access grant, signed as the ORG by the steward's
      // resolved credential. Best-effort: the app-level removal already stands; a failed revoke is
      // surfaced so the steward can retry.
      if (b.memberAccessDelegation) {
        const sign = await signHashFor(resolveVia(profile?.credential, session.via), org.orgAgent as Address, { token: session.token });
        const rev = await revokeGrantedDelegation(b.memberAccessDelegation, sign);
        if (!rev.ok) setErr(`member removed, but the on-chain grant revoke failed: ${rev.error}`);
      }
      // Spec 410 §8 — DEPARTURE: the organization's unilateral revocation of the membership credential, signed as
      // the org by the steward, written to both vaults (hers may refuse — the revocation stands on the org's copy).
      // Best-effort like the grant revoke: the removal already stands; a miss is said, never hidden.
      try {
        const sign = await signHashFor(resolveVia(profile?.credential, session.via), org.orgAgent as Address, { token: session.token });
        const rv = await revokeRelationshipCredential({ session: { token: session.token }, org: org.orgAgent as Address, member: member as Address, as: 'object', sign, reason: 'removed by a steward' });
        if (!rv.ok && !/no membership credential/.test(rv.error)) setErr((prev) => `${prev ? `${prev} · ` : ''}the membership credential was not revoked: ${rv.error}`);
      } catch (e) { setErr((prev) => `${prev ? `${prev} · ` : ''}the membership credential was not revoked: ${e instanceof Error ? e.message : String(e)}`); }
      reload();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally { setRemoving(null); }
  }, [token, session, profile?.credential, org.orgAgent, reload]);

  return (
    <div className="dash-section" style={{ marginTop: '1.25rem' }}>
      <h3>Members</h3>
      {err && <p className="manage-card-blurb" style={{ color: 'var(--c-danger, #dc2626)' }}>{err}</p>}
      {!loaded ? (
        <p className="manage-card-blurb">Loading members…</p>
      ) : (
        <div className="manage-grid">
          {/* The viewer stewards this org (that's how they reached this panel) — show them FIRST,
              always: an org is never "empty" to its own steward. If their membership delegation is
              recorded (org create now mints it), the same card carries the Member badge too. */}
          {(() => {
            const selfLc = (agentAddress ?? '').toLowerCase();
            const selfMember = members.some((m) => m.orgAgent.toLowerCase() === selfLc);
            return (
              <div className="manage-card">
                <div className="manage-card-head">
                  <span className="manage-card-label">You</span>
                  <span className="manage-card-badge live">Steward</span>
                  {selfMember && <span className="manage-card-badge">Member</span>}
                </div>
                {agentAddress && <div style={{ margin: '.45rem 0' }}><AddressChip address={agentAddress} size="sm" /></div>}
                <p className="manage-card-blurb" style={{ margin: 0 }}>
                  You hold this organization&rsquo;s stewardship delegation — admin read/oversight of its data.
                  {!selfMember && ' (No membership delegation recorded — orgs created from now on add one automatically.)'}
                </p>
              </div>
            );
          })()}
          {members
            .filter((m) => m.orgAgent.toLowerCase() !== (agentAddress ?? '').toLowerCase())
            .map((m, i) => (
              <MemberCard
                key={`${m.orgAgent}-${i}`}
                m={m}
                onRemove={() => void remove(m.orgAgent)}
                removing={removing === m.orgAgent}
              />
            ))}
        </div>
      )}
      {loaded && members.filter((m) => m.orgAgent.toLowerCase() !== (agentAddress ?? '').toLowerCase()).length === 0 && (
        <p className="manage-card-blurb" style={{ marginTop: '.7rem' }}>
          No other members yet — they&rsquo;re added when they accept an invitation (or join the channels) and grant their membership delegation.
        </p>
      )}
    </div>
  );
}

export function OrgDetail({ org, token, onBack }: { org: MyOrg; token: string | null; onBack: () => void }) {
  const created = org.createdAt ? new Date(org.createdAt).toLocaleString() : '—';
  // The roles this org can offer, read from ITS OWN library — the same packages the harness
  // composes from, so the panel can never offer a role whose definition the host would fail to
  // load. A package that declares `skills:` is a role; everything else is one of their skills.
  const [archetypes, setArchetypes] = useState<{ slug: string; description?: string }[]>([]);
  useEffect(() => {
    if (!token || !org.orgAgent) return;
    void (async () => {
      try {
        const r = await fetch(`/connect/library?org=${org.orgAgent}&folder=skills&name=SKILL.md`, { headers: { authorization: `Bearer ${token}` } });
        const b = (await r.json().catch(() => ({}))) as { artifacts?: Array<{ folder?: string; name?: string; bytesB64?: string }> };
        const roles: { slug: string; description?: string }[] = [];
        for (const a of b.artifacts ?? []) {
          if (a.name !== 'SKILL.md' || !a.folder?.startsWith('skills/')) continue;
          const slug = a.folder.slice('skills/'.length);
          if (!slug || slug.includes('/') || !a.bytesB64) continue;
          const text = new TextDecoder().decode(Uint8Array.from(atob(a.bytesB64), (c) => c.charCodeAt(0)));
          const fm = /^---\n([\s\S]*?)\n---/.exec(text)?.[1] ?? '';
          if (!/^skills:\s*\S/m.test(fm) && !/^archetype:\s*true/m.test(fm)) continue;
          const description = /^description:\s*(.+)$/m.exec(fm)?.[1]?.replace(/^["']|["']$/g, '').trim();
          roles.push({ slug, ...(description ? { description } : {}) });
        }
        setArchetypes(roles.sort((x, y) => x.slug.localeCompare(y.slug)));
      } catch { /* no library, no roles to offer — the panel says so */ }
    })();
  }, [token, org.orgAgent]);
  return (
    <div>
      <button type="button" className="btn-ghost" style={{ marginBottom: '1rem', fontSize: '.85rem' }} onClick={onBack}>
        ← All organizations
      </button>

      {/* Identity */}
      <div className="dash-section">
        <h2><BuildingIcon size={16} /> {org.orgName || '(unnamed org)'}</h2>
        <Fact label="Name"><code>{org.orgName || '—'}</code></Fact>
        <Fact label="Address">
          <AddressChip address={org.orgAgent} size="sm" />{' '}
          <ExplorerLink address={org.orgAgent} label="explorer ↗" />
        </Fact>
        <Fact label="Kind">{purposeLabel(org.purpose)}</Fact>
        <Fact label="Created for">{org.requestedBy || '—'}</Fact>
        <Fact label="Created">{created}</Fact>
        <Fact label="Stewardship">You steward this organization — your credential signs for it</Fact>
        {org.proofHash && <Fact label="Link proof"><code>{short(org.proofHash)}</code></Fact>}
      </div>

      {/* Delegations */}
      <div className="dash-section" style={{ marginTop: '1.25rem' }}>
        <h3 className="subhead" style={{ display: 'flex', alignItems: 'center', gap: '.35rem', marginBottom: '.6rem' }}><LinkIcon size={14} /> Delegations</h3>
        <div className="manage-grid">
          {org.delegation && <DelegationCard kind="App access" d={org.delegation} />}
          {org.membershipDelegation && <DelegationCard kind="Membership" d={org.membershipDelegation} />}
          {org.stewardshipDelegation && <DelegationCard kind="Stewardship" d={org.stewardshipDelegation} />}
        </div>
      </div>

      {/* Members — agents that delegated to this org (read each over their grant) */}
      <OrgMembers org={org} token={token} />

      {/* Stewardship — manage + read the org's own vault */}
      {org.stewardshipDelegation ? (
        <>
          <OrgProfileManager delegation={org.stewardshipDelegation} />
          <VaultReader
            title="All organization records"
            hint="Every record in the org's vault, read with your stewardship delegation (org → you). The org owns this data; you oversee it."
            delegation={org.stewardshipDelegation}
          />
        </>
      ) : (
        <div className="dash-section" style={{ marginTop: '1.25rem' }}>
          <h3 className="subhead" style={{ margin: 0 }}>Organization data</h3>
          <p className="manage-card-blurb">No stewardship delegation on this org — can&rsquo;t read or manage its vault.</p>
        </div>
      )}

      {/* Membership read — what the org sees about you, via the OTHER delegation */}
      {org.membershipDelegation ? (
        <VaultReader
          title="Your member record (what this org can read about you)"
          hint="Read from YOUR vault using the membership delegation (you → org). This is exactly what the org is entitled to see about you as its member — it stays in your vault."
          delegation={org.membershipDelegation}
        />
      ) : (
        <div className="dash-section" style={{ marginTop: '1.25rem' }}>
          <h3 className="subhead" style={{ margin: 0 }}>Your member record</h3>
          <p className="manage-card-blurb">No membership delegation on this org — nothing to read.</p>
        </div>
      )}

      {/* Archetype dispatch — this org's specialists, offered to another organization.
          Shown for every org: the archetype list is what makes it meaningful, and an org whose
          library defines none says so in the panel rather than being hidden, which is the
          difference between "we host nothing" and "this feature does not exist here". */}
      <div className="dash-section" style={{ marginTop: '1.25rem' }}>
        <OrgArchetypeGrantsPanel org={org.orgAgent as Address} archetypes={archetypes} />
      </div>
    </div>
  );
}
