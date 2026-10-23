'use client';
// ADMIN (Global.Church, 2026-10-09) — for the people who run this Home: how many people have a GCID, how many
// organizations, and what the estate costs on Azure. The Overview tab is counts and dollars only; the Organizations tab
// (AdminOrganizations.tsx, 2026-10-22) lists organizations with their managers' emails, and each view is recorded.
// The server (`/connect/admin/*`) decides who may see it; to anyone else this page shows the refusal.
import { useCallback, useEffect, useState } from 'react';
import { useSession } from '../../context/session';
import { PageHead, Section, Stats, Stat, List, Row, Empty, ErrorNote, Note, Button, Meta, SkeletonRows, Tabs } from '../../ui';
import { budgetTone, type CostsResult, type CostsView } from '../../lib/azure-costs';
import type { AccountsView, OrgTypesView } from '../../../server/connect/admin';
import { AdminOrganizations } from './AdminOrganizations';

type Load<T> = T | null | undefined;

const METHOD_LABEL: Record<string, string> = { email: 'Email', phone: 'Phone', google: 'Google', passkey: 'Passkey', other: 'Other (wallet, YouVersion…)' };
const when = (t: number) => new Date(t).toLocaleString([], { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' });
const dayLabel = (d: string) => new Date(`${d}T12:00:00Z`).toLocaleDateString([], { month: 'short', day: 'numeric' });
const plus = (n: number | null) => (n === null ? '—' : n > 0 ? `+${n}` : String(n));

function money(n: number | null, currency: string): string {
  if (n === null) return 'unavailable';
  return new Intl.NumberFormat([], { style: 'currency', currency, maximumFractionDigits: n >= 100 ? 0 : 2 }).format(n);
}

async function getJson<T>(path: string, token: string): Promise<{ ok: true; body: T } | { ok: false; status: number; error: string }> {
  const r = await fetch(path, { headers: { authorization: `Bearer ${token}` } }).catch(() => null);
  if (!r) return { ok: false, status: 0, error: 'The Home did not answer.' };
  const j = (await r.json().catch(() => ({}))) as T & { error?: string };
  return r.ok ? { ok: true, body: j } : { ok: false, status: r.status, error: j.error ?? `HTTP ${r.status}` };
}

export function AdminView() {
  const { session } = useSession();
  const [accounts, setAccounts] = useState<Load<AccountsView>>(undefined);
  const [costs, setCosts] = useState<Load<CostsResult>>(undefined);
  const [orgTypes, setOrgTypes] = useState<Load<OrgTypesView>>(undefined);
  const [refused, setRefused] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  // Overview (counts and costs) or Organizations (the list with contacts, 2026-10-22). The hash keeps the tab on reload.
  const [tab, setTabState] = useState<'overview' | 'organizations'>('overview');
  useEffect(() => { if (window.location.hash === '#organizations') setTabState('organizations'); }, []);
  const setTab = (t: 'overview' | 'organizations') => {
    setTabState(t);
    window.history.replaceState(null, '', t === 'organizations' ? '#organizations' : window.location.pathname + window.location.search);
  };

  const load = useCallback(async (refresh: boolean) => {
    if (!session) return;
    setError(null);
    const q = refresh ? '?refresh=1' : '';
    const [a, c, t] = await Promise.all([
      getJson<AccountsView>(`/connect/admin/accounts${q}`, session.token),
      getJson<CostsResult>(`/connect/admin/azure-costs${q}`, session.token),
      getJson<OrgTypesView>('/connect/admin/org-types', session.token),
    ]);
    if ((!a.ok && a.status === 403) || (!c.ok && c.status === 403)) { setRefused(true); return; }
    if (t.ok) setOrgTypes(t.body); else setOrgTypes(null);
    if (a.ok) setAccounts(a.body); else { setAccounts(null); setError(a.error); }
    if (c.ok) setCosts(c.body); else { setCosts(null); setError(c.error); }
  }, [session]);
  useEffect(() => { void load(false); }, [load]);

  const refresh = async () => { setBusy(true); await load(true); setBusy(false); };

  if (refused) {
    return (
      <>
        <PageHead title="Admin" />
        <Empty title="This page is for the people who run this Home">Your account is not on its admin list. If you should be, ask an admin to add your address.</Empty>
      </>
    );
  }

  return (
    <>
      <PageHead
        title="Admin"
        description={tab === 'overview' ? 'How many people use GCID, and what running it costs on Azure.' : 'The organizations each app brought to GCID, with their type and who to contact.'}
        actions={tab === 'overview' ? <Button size="sm" onClick={() => void refresh()} disabled={busy || !session}>{busy ? 'Refreshing…' : 'Refresh'}</Button> : undefined}
      />
      <Tabs label="Admin" value={tab} onChange={setTab} items={[{ id: 'overview', label: 'Overview' }, { id: 'organizations', label: 'Organizations' }]} />
      {tab === 'organizations' ? (
        session && <AdminOrganizations session={session} />
      ) : (
        <>
          {error && <ErrorNote>{error}</ErrorNote>}
          <AccountsSection a={accounts} />
          <OrgTypesSection t={orgTypes} />
          <CostsSection c={costs} />
        </>
      )}
    </>
  );
}

function AccountsSection({ a }: { a: Load<AccountsView> }) {
  if (a === undefined) return <Section title="GCID accounts"><SkeletonRows rows={2} lead /></Section>;
  if (a === null) return <Section title="GCID accounts"><Empty title="Account numbers are unavailable" /></Section>;
  const since = a.trackingSince ? `tracking since ${dayLabel(a.trackingSince)}` : 'tracking starts today';
  const methods = Object.entries(a.byMethod).filter(([, n]) => n > 0);
  return (
    <Section title="GCID accounts" aside={<Meta>as of {when(a.asOf)}</Meta>} testId="admin-accounts">
      <Stats>
        <Stat label="people with a GCID" value={a.accounts.toLocaleString()} testId="admin-accounts-total" />
        {/* Until 7 / 30 days of daily counts exist, the tile shows growth since counting began, and says so. */}
        <Stat label="new in 7 days" value={plus(a.new7d ?? a.newSinceTracking ?? null)} hint={a.new7d === null ? `since ${dayLabel(a.trackingSince ?? '')}, when counting began` : undefined} />
        <Stat label="new in 30 days" value={plus(a.new30d ?? a.newSinceTracking ?? null)} hint={a.new30d === null ? `since ${dayLabel(a.trackingSince ?? '')}, when counting began` : undefined} />
        <Stat label="organizations" value={a.organizations.toLocaleString()} hint={`+${a.newOrganizations7d} this week · +${a.newOrganizations30d} in 30 days`} />
        <Stat label="workspaces" value={a.workspaces.toLocaleString()} hint="app workspaces, e.g. Gather27" />
      </Stats>
      {/* Two or three days draw a single slope that says nothing; the chart waits for a week of daily counts. */}
      {a.history.length >= 7 && <Sparkline points={a.history.map((s) => ({ label: s.date, value: s.accounts }))} title="People with a GCID, by day" />}
      {methods.length > 0 && (
        <List>
          {methods.map(([m, n]) => (
            <Row key={m} title={METHOD_LABEL[m] ?? m} meta={`${n.toLocaleString()} ${n === 1 ? 'person signs' : 'people sign'} in this way`} />
          ))}
        </List>
      )}
      <Note>A person counts once however many ways they sign in, so the methods add up to more than the total. Growth is measured from the daily count this page keeps, {since}.</Note>
      {(a.testAccounts ?? 0) > 0 && (
        <Note>
          {a.testAccounts.toLocaleString()} test {a.testAccounts === 1 ? 'identity is' : 'identities are'} not counted here: people who signed in as name+gcidtest@…, and organizations only they belong to.
        </Note>
      )}
    </Section>
  );
}

/** The type each organization was given when it was created, and the "Other" answers in the person's own words:
 *  the list the team reads to decide what the ontology is missing (2026-10-21). */
function OrgTypesSection({ t }: { t: Load<OrgTypesView> }) {
  const title = 'Organization types';
  if (t === undefined) return <Section title={title}><SkeletonRows rows={2} lead /></Section>;
  if (t === null) return <Section title={title}><Empty title="Organization types are unavailable" /></Section>;
  const typed = t.byType.reduce((n, x) => n + x.count, 0) + t.other.length;
  return (
    <Section title={title} aside={<Meta>as of {when(t.asOf)}</Meta>} testId="admin-org-types">
      <Stats>
        <Stat label="with a type" value={typed.toLocaleString()} />
        <Stat label="answered Other" value={t.other.length.toLocaleString()} testId="admin-org-types-other-count" />
        <Stat label="no type yet" value={t.noType.toLocaleString()} hint="created before the question was asked" />
      </Stats>
      {t.byType.length > 0 && (
        <List>
          {t.byType.map((x) => (
            <Row key={x.iri} title={x.label} meta={`${x.count.toLocaleString()} ${x.count === 1 ? 'organization' : 'organizations'}`} />
          ))}
        </List>
      )}
      <h3 className="subhead" style={{ marginTop: '1rem' }}>Other answers</h3>
      {t.other.length === 0 ? (
        <Note>No one has answered Other yet.</Note>
      ) : (
        <List>
          {t.other.map((o, i) => (
            <Row key={`${o.at ?? 'x'}-${i}`} title={o.text} meta={o.at ? when(o.at) : undefined} testId={`admin-org-type-other-${i}`} />
          ))}
        </List>
      )}
      <Note>Other answers are what people typed when no listed type fit. Use them to decide what the organization-type list in the ontology is missing.</Note>
    </Section>
  );
}

function CostsSection({ c }: { c: Load<CostsResult> }) {
  if (c === undefined) return <Section title="Azure spending"><SkeletonRows rows={3} lead /></Section>;
  if (c === null) return <Section title="Azure spending"><Empty title="Azure spending is unavailable" /></Section>;
  if (!c.ok) return <Section title="Azure spending"><Empty title="Azure spending is unavailable">{c.reason}</Empty></Section>;
  const cur = c.currency;
  const tone = budgetTone(c);
  const monthName = new Date(`${c.monthStart}T12:00:00Z`).toLocaleDateString([], { month: 'long' });
  return (
    <Section title="Azure spending" aside={<Meta>as of {when(c.asOf)} · Azure&rsquo;s figures lag up to a day</Meta>} testId="admin-azure">
      <Stats>
        <Stat label={`${monthName} so far`} value={money(c.monthToDate, cur)} {...(tone ? { tone } : {})} testId="admin-azure-mtd" />
        <Stat label="forecast for the month" value={money(c.forecastMonthEnd, cur)} {...(c.budget && (c.forecastMonthEnd ?? 0) > c.budget.amount ? { tone: 'warn' as const } : {})} />
        <Stat label="budget" value={c.budget ? money(c.budget.amount, cur) : 'none set'} hint={c.budget?.name} />
        <Stat label="last month" value={money(c.lastMonth, cur)} />
      </Stats>
      {c.budget && <BudgetBar v={c} />}
      {c.daily.length > 1 && <DailyBars days={c.daily} currency={cur} />}
      <List>
        {c.byGroup.length === 0 ? (
          <Row title="No charges yet this month" />
        ) : (
          c.byGroup.map((g) => (
            <Row key={g.group} title={g.label} meta={g.label !== g.group ? g.group : undefined} side={<span style={{ fontVariantNumeric: 'tabular-nums' }}>{money(g.cost, cur)}</span>} />
          ))
        )}
      </List>
    </Section>
  );
}

function BudgetBar({ v }: { v: CostsView }) {
  const b = v.budget!;
  const spent = Math.min(1, v.monthToDate / b.amount);
  const forecast = v.forecastMonthEnd === null ? null : Math.min(1, v.forecastMonthEnd / b.amount);
  const tone = budgetTone(v);
  const fill = tone === 'danger' ? 'var(--color-danger, #b3261e)' : tone === 'warn' ? 'var(--c-warn, #b45309)' : 'var(--c-success, #15803d)';
  return (
    <div style={{ margin: '12px 0 4px' }} aria-label={`${Math.round(spent * 100)}% of the monthly budget spent`}>
      <div style={{ position: 'relative', height: 10, borderRadius: 5, background: 'var(--color-border, #e5e7eb)' }}>
        {forecast !== null && <div style={{ position: 'absolute', inset: 0, width: `${forecast * 100}%`, borderRadius: 5, background: fill, opacity: 0.25 }} />}
        <div style={{ position: 'absolute', inset: 0, width: `${Math.max(1, spent * 100)}%`, borderRadius: 5, background: fill }} />
      </div>
      <Meta>{Math.round(spent * 100)}% of the budget spent{forecast !== null ? ` · on course for ${Math.round((v.forecastMonthEnd! / b.amount) * 100)}%` : ''}</Meta>
    </div>
  );
}

function DailyBars({ days, currency }: { days: { day: string; cost: number }[]; currency: string }) {
  const max = Math.max(...days.map((d) => d.cost), 0.01);
  const w = 600, h = 90, gap = 2, bw = Math.max(2, w / days.length - gap);
  return (
    <figure style={{ margin: '12px 0' }}>
      <figcaption><Meta>Daily cost, last {days.length} days · highest {money(max, currency)}</Meta></figcaption>
      <svg viewBox={`0 0 ${w} ${h + 16}`} width="100%" role="img" aria-label="Daily Azure cost" style={{ display: 'block', maxWidth: '100%' }}>
        {days.map((d, i) => {
          const bh = Math.max(1, (d.cost / max) * h);
          return (
            <rect key={d.day} x={i * (bw + gap)} y={h - bh} width={bw} height={bh} rx={1} fill="var(--c-primary, #b45309)">
              <title>{`${dayLabel(d.day)}: ${money(d.cost, currency)}`}</title>
            </rect>
          );
        })}
        <text x={0} y={h + 13} fontSize={11} fill="var(--color-text-muted, #6b7280)">{dayLabel(days[0]!.day)}</text>
        <text x={w} y={h + 13} fontSize={11} textAnchor="end" fill="var(--color-text-muted, #6b7280)">{dayLabel(days[days.length - 1]!.day)}</text>
      </svg>
    </figure>
  );
}

function Sparkline({ points, title }: { points: { label: string; value: number }[]; title: string }) {
  const w = 600, h = 60, pad = 4;
  const min = Math.min(...points.map((p) => p.value));
  const max = Math.max(...points.map((p) => p.value));
  const span = Math.max(1, max - min);
  const x = (i: number) => pad + (i / (points.length - 1)) * (w - 2 * pad);
  const y = (v: number) => h - pad - ((v - min) / span) * (h - 2 * pad);
  const line = points.map((p, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)},${y(p.value).toFixed(1)}`).join(' ');
  const last = points[points.length - 1]!;
  return (
    <figure style={{ margin: '12px 0' }}>
      <figcaption><Meta>{title} · {dayLabel(points[0]!.label)} → {dayLabel(last.label)}</Meta></figcaption>
      <svg viewBox={`0 0 ${w} ${h}`} width="100%" role="img" aria-label={title} style={{ display: 'block', maxWidth: '100%' }}>
        <path d={`${line} L${x(points.length - 1).toFixed(1)},${h} L${x(0).toFixed(1)},${h} Z`} fill="var(--c-primary, #b45309)" opacity={0.12} />
        <path d={line} fill="none" stroke="var(--c-primary, #b45309)" strokeWidth={2} />
        <circle cx={x(points.length - 1)} cy={y(last.value)} r={3.5} fill="var(--c-primary, #b45309)" />
      </svg>
    </figure>
  );
}
