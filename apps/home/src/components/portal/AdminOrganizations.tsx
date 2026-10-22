'use client';
// ADMIN → ORGANIZATIONS (Global.Church, 2026-10-22). Every organization an app brought to this Home — Gather is the
// only app today — with its type and the email of each person who manages it, searchable and filterable, and a CSV
// download. Replaces the one-at-a-time Contact lookup. The server (`/connect/admin/organizations`) decides who may
// see it and records each view; the last views are shown at the foot of the page.
import { useCallback, useEffect, useMemo, useState } from 'react';
import { Section, Stats, Stat, Empty, ErrorNote, Note, Button, Meta, Mono, SkeletonRows, SearchInput, FilterChip, Toolbar } from '../../ui';
import type { OrganizationRow, OrganizationsView } from '../../../server/connect/admin';

const when = (t: number) => new Date(t).toLocaleString([], { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' });
const day = (t: number) => new Date(t).toLocaleDateString([], { year: 'numeric', month: 'short', day: 'numeric' });
const short = (a: string) => `${a.slice(0, 6)}…${a.slice(-4)}`;

/** The filter key for a row's type: an ontology IRI, 'other', or 'none'. */
const typeKey = (o: OrganizationRow) => (!o.type ? 'none' : o.type.iri === null ? 'other' : o.type.iri);
const typeText = (o: OrganizationRow) => (!o.type ? '' : o.type.iri === null ? `Other: ${o.type.other ?? ''}` : o.type.label ?? '');

function csv(rows: OrganizationRow[]): string {
  const cell = (v: unknown) => {
    const s = String(v ?? '');
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  const head = ['Organization', 'Organization address', 'Type', 'Other answer', 'Contact emails', 'Managers', 'Members', 'Created'];
  const body = rows.map((o) => [
    o.name, o.org, o.type?.iri === null ? 'Other' : o.type?.label ?? '', o.type?.iri === null ? o.type.other ?? '' : '',
    o.contacts.map((c) => c.email).filter(Boolean).join('; '), o.contacts.length, o.members,
    o.createdAt ? new Date(o.createdAt).toISOString().slice(0, 10) : '',
  ].map(cell).join(','));
  return [head.join(','), ...body].join('\r\n');
}

export function AdminOrganizations({ token }: { token: string }) {
  const [app, setApp] = useState('gather-app');
  const [view, setView] = useState<OrganizationsView | null | undefined>(undefined);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [q, setQ] = useState('');
  const [type, setType] = useState<string>('all');
  const [noEmail, setNoEmail] = useState(false);
  const [showTest, setShowTest] = useState(false);

  const load = useCallback(async () => {
    setBusy(true);
    setError(null);
    const r = await fetch(`/connect/admin/organizations?app=${encodeURIComponent(app)}`, { headers: { authorization: `Bearer ${token}` } }).catch(() => null);
    const j = (await r?.json().catch(() => null)) as (OrganizationsView & { error?: string }) | null;
    setBusy(false);
    if (r?.ok && j) setView(j);
    else { setView(null); setError(j?.error ?? (r ? `HTTP ${r.status}` : 'The Home did not answer.')); }
  }, [app, token]);
  useEffect(() => { void load(); }, [load]);

  const base = useMemo(() => (view?.orgs ?? []).filter((o) => showTest || !o.test), [view, showTest]);
  const types = useMemo(() => {
    const m = new Map<string, { label: string; count: number }>();
    for (const o of base) {
      const k = typeKey(o);
      const label = k === 'none' ? 'No type yet' : k === 'other' ? 'Other' : o.type?.label ?? k;
      m.set(k, { label, count: (m.get(k)?.count ?? 0) + 1 });
    }
    // Listed types by count, then Other, then No type.
    return [...m.entries()].sort(([a, x], [b, y]) => {
      const rank = (k: string) => (k === 'other' ? 1 : k === 'none' ? 2 : 0);
      return rank(a) - rank(b) || y.count - x.count || x.label.localeCompare(y.label);
    });
  }, [base]);
  const shown = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return base.filter((o) => {
      if (type !== 'all' && typeKey(o) !== type) return false;
      if (noEmail && o.contacts.some((c) => c.email)) return false;
      if (!needle) return true;
      return [o.name, o.org, typeText(o), ...o.contacts.flatMap((c) => [c.email ?? '', c.account])].some((s) => s.toLowerCase().includes(needle));
    });
  }, [base, q, type, noEmail]);

  const download = () => {
    const blob = new Blob([csv(shown)], { type: 'text/csv' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `${view?.apps.find((x) => x.id === app)?.label ?? app}-organizations-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(a.href);
  };

  const withEmail = base.filter((o) => o.contacts.some((c) => c.email)).length;
  const testCount = (view?.orgs ?? []).filter((o) => o.test).length;

  return (
    <>
      <Toolbar>
        <label className="admin-orgs__app">
          <span>App</span>
          <select value={app} onChange={(e) => setApp(e.target.value)} data-testid="admin-orgs-app">
            {(view?.apps ?? [{ id: 'gather-app', label: 'Gather' }]).map((a) => <option key={a.id} value={a.id}>{a.label}</option>)}
          </select>
        </label>
        <div className="admin-orgs__search">
          <SearchInput value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search name, email, type or address" aria-label="Search organizations" data-testid="admin-orgs-q" />
        </div>
        <Button size="sm" onClick={download} disabled={!shown.length} data-testid="admin-orgs-csv">Download CSV</Button>
        <Button size="sm" onClick={() => void load()} disabled={busy}>{busy ? 'Loading…' : 'Refresh'}</Button>
      </Toolbar>
      {error && <ErrorNote>{error}</ErrorNote>}
      {view === undefined && <SkeletonRows rows={5} lead />}
      {view === null && !error && <Empty title="Organizations are unavailable" />}
      {view && (
        <>
          <Stats>
            <Stat label="organizations" value={base.length.toLocaleString()} testId="admin-orgs-total" />
            <Stat label="with a contact email" value={withEmail.toLocaleString()} />
            <Stat label="no type yet" value={(types.find(([k]) => k === 'none')?.[1].count ?? 0).toLocaleString()} />
          </Stats>
          <div className="admin-orgs__filters" role="group" aria-label="Filter by type">
            <FilterChip active={type === 'all'} count={base.length} onClick={() => setType('all')}>All types</FilterChip>
            {types.map(([k, t]) => (
              <FilterChip key={k} active={type === k} count={t.count} onClick={() => setType(type === k ? 'all' : k)} data-testid={`admin-orgs-type-${k === 'none' || k === 'other' ? k : k.split('-').pop()}`}>{t.label}</FilterChip>
            ))}
            <span className="admin-orgs__sep" aria-hidden />
            <FilterChip active={noEmail} onClick={() => setNoEmail(!noEmail)}>No contact email</FilterChip>
            {testCount > 0 && <FilterChip active={showTest} count={testCount} onClick={() => setShowTest(!showTest)}>Show test accounts</FilterChip>}
          </div>
          {!view.emails && <Note>The contact directory is not switched on for this Home (no key configured), so emails are not shown.</Note>}
          <Section title="Organizations" count={shown.length} aside={<Meta>as of {when(view.asOf)}</Meta>} testId="admin-orgs">
            {shown.length === 0 ? (
              <Note>{base.length === 0 ? 'No organizations from this app yet.' : 'No organizations match.'}</Note>
            ) : (
              <div className="admin-orgs__scroll">
                <table className="admin-orgs__table">
                  <thead>
                    <tr><th>Organization</th><th>Type</th><th>Contact</th><th>Members</th><th>Created</th></tr>
                  </thead>
                  <tbody>
                    {shown.map((o) => (
                      <tr key={o.org} data-testid={`admin-orgs-row-${o.org.slice(2, 10)}`}>
                        <td>
                          <strong>{o.name || 'Unnamed organization'}</strong>
                          {o.test && <> <Meta>test</Meta></>}
                          <div><Mono title={o.org}>{short(o.org)}</Mono></div>
                        </td>
                        <td>
                          {!o.type ? <Meta>No type yet</Meta> : o.type.iri === null ? <>Other <Meta>“{o.type.other}”</Meta></> : o.type.label}
                        </td>
                        <td>
                          {o.contacts.length === 0 && <Meta>No manager found</Meta>}
                          {o.contacts.map((c) => (
                            <div key={c.account}>
                              {c.email ? <a href={`mailto:${c.email}`}>{c.email}</a> : <span title={c.account}><Meta>No email on file ({short(c.account)})</Meta></span>}
                            </div>
                          ))}
                        </td>
                        <td>{o.members || '—'}</td>
                        <td>{o.createdAt ? day(o.createdAt) : '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Section>
          <Note>
            Contacts are the people who manage each organization, at the email they sign in with. Members are counted, not listed. An account
            created before 21 Oct picks up its email at its next sign-in. Every time this list is opened is recorded with your account and the time.
          </Note>
          {view.views.length > 0 && (
            <Note>
              Recently opened by: {view.views.map((v) => `${short(v.by)} ${when(v.at)}`).join(' · ')}
            </Note>
          )}
        </>
      )}
    </>
  );
}
