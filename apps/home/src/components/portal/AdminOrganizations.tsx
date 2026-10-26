'use client';
// ADMIN → ORGANIZATIONS (Global.Church, 2026-10-22; operator directory 2026-10-23). Every organization an app brought
// to this Home — Gather is the only app today — with its type and how to reach it, searchable and filterable.
//
// With the operator directory (the server says `masked`), addresses are MASKED. A full address comes from "Show" on
// one row (recorded) or from an export that a SECOND admin approved: one admin requests, another approves, the
// requester downloads it once within 30 minutes. Every step is recorded in the operator org's vault and shown here.
// Without it (no operator org configured yet), the page is what it was: full addresses and a direct CSV.
import { useCallback, useEffect, useMemo, useState } from 'react';
import type { Address } from '@agenticprimitives/types';
import { Section, Stats, Stat, Empty, ErrorNote, Note, Button, Meta, Mono, SkeletonRows, SearchInput, FilterChip, Toolbar } from '../../ui';
import type { OrganizationRow, OrganizationsView } from '../../../server/connect/admin';
import type { Session } from '../../context/session';
import { fetchProfile } from '../../connect-client';
import { resolveVia, signHashFor } from '../../home/onboarding';
import { issueOperatorDirectoryDelegation } from '../../lib/delegation';
import { INTERACTIONS_SERVICE_SA, MCP_SERVER_ID } from '../../lib/inbox-delivery';

const when = (t: number) => new Date(t).toLocaleString([], { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' });
const day = (t: number) => new Date(t).toLocaleDateString([], { year: 'numeric', month: 'short', day: 'numeric' });
const short = (a: string) => `${a.slice(0, 6)}…${a.slice(-4)}`;

/** The account this session belongs to (the `sub` of the Home session JWT), lower-case. */
function myAccount(token: string): string {
  try {
    const p = JSON.parse(atob(token.split('.')[1]!.replace(/-/g, '+').replace(/_/g, '/'))) as { sub?: string };
    return (p.sub?.match(/0x[0-9a-fA-F]{40}$/)?.[0] ?? '').toLowerCase();
  } catch {
    return '';
  }
}

/** The filter key for a row's type: an ontology IRI, 'other', or 'none'. */
const typeKey = (o: OrganizationRow) => (!o.type ? 'none' : o.type.iri === null ? 'other' : o.type.iri);
/** Does this organization have any email to reach it by: its own contact, or a manager's. */
const reachable = (o: OrganizationRow) => !!o.orgContact || o.contacts.some((c) => c.email);
const typeText = (o: OrganizationRow) => (!o.type ? '' : o.type.iri === null ? `Other: ${o.type.other ?? ''}` : o.type.label ?? '');

/** The CSV, from the rows on screen; `emails` overrides what the rows carry (the full addresses of an approved export). */
function csv(rows: OrganizationRow[], emails?: Map<string, string | null>): string {
  const cell = (v: unknown) => {
    const s = String(v ?? '');
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  const em = (account: string, fallback: string | null | undefined) => (emails ? emails.get(account) ?? '' : fallback ?? '');
  const head = ['Organization', 'Organization address', 'Type', 'Other answer', 'Organization contact', 'Manager emails', 'Managers', 'Members', 'Created'];
  const body = rows.map((o) => [
    o.name, o.org, o.type?.iri === null ? 'Other' : o.type?.label ?? '', o.type?.iri === null ? o.type.other ?? '' : '',
    em(o.org, o.orgContact?.email), o.contacts.map((c) => em(c.account, c.email)).filter(Boolean).join('; '), o.contacts.length, o.members,
    o.createdAt ? new Date(o.createdAt).toISOString().slice(0, 10) : '',
  ].map(cell).join(','));
  return [head.join(','), ...body].join('\r\n');
}

/** All accounts (2026-10-26): one row per GCID account — the account, its sign-in email, how it signs in. */
function accountsCsv(rows: { account: string; email: string | null }[], methods: Map<string, string[]>): string {
  const cell = (v: unknown) => {
    const s = String(v ?? '');
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  return [['Account', 'Email', 'Signs in with'].join(','), ...rows.map((r) => [r.account, r.email ?? '', (methods.get(r.account) ?? []).join('; ')].map(cell).join(','))].join('\r\n');
}

const METHOD_WORDS: Record<string, string> = { email: 'Email', phone: 'Phone', google: 'Google', passkey: 'Passkey', other: 'Other' };

function save(name: string, text: string) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([text], { type: 'text/csv' }));
  a.download = name;
  a.click();
  URL.revokeObjectURL(a.href);
}

interface ExportSummary { id: string; app: string; requestedBy: string; requestedAt: number; note?: string; approvedBy?: string; approvedAt?: number; deniedBy?: string; count: number; status: 'pending' | 'approved' | 'downloaded' | 'denied' | 'expired' }
interface AuditEntry { at: number; by: string; kind: string; accounts?: number; account?: string; exportId?: string }

const AUDIT_WORDS: Record<string, string> = {
  list: 'opened the list', reveal: 'showed one address', 'export-request': 'requested an export', 'export-approve': 'approved an export',
  'export-deny': 'denied an export', 'export-fetch': 'downloaded an export', import: 'imported the old directory', enable: 'enabled the directory',
};

export function AdminOrganizations({ session }: { session: Session }) {
  const token = session.token;
  const me = useMemo(() => myAccount(token), [token]);
  const [app, setApp] = useState('gather-app');
  const [view, setView] = useState<OrganizationsView | null | undefined>(undefined);
  const [error, setError] = useState<string | null>(null);
  const [notEnabled, setNotEnabled] = useState(false);
  const [busy, setBusy] = useState(false);
  const [q, setQ] = useState('');
  const [type, setType] = useState<string>('all');
  const [noEmail, setNoEmail] = useState(false);
  const [showTest, setShowTest] = useState(false);
  const [revealed, setRevealed] = useState<Record<string, string | null>>({});
  const [exportsList, setExports] = useState<ExportSummary[]>([]);
  const [activity, setActivity] = useState<AuditEntry[]>([]);
  const [note, setNote] = useState<string | null>(null);

  const directory = useCallback(async <T,>(action: string, extra: Record<string, unknown> = {}): Promise<T> => {
    const r = await fetch('/connect/admin/directory', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
      body: JSON.stringify({ action, ...extra }),
    }).catch(() => null);
    const j = (await r?.json().catch(() => null)) as (T & { error?: string }) | null;
    if (!r?.ok || !j) throw new Error(j?.error ?? (r ? `HTTP ${r.status}` : 'The Home did not answer.'));
    return j;
  }, [token]);

  const loadSide = useCallback(async () => {
    try { setExports((await directory<{ requests: ExportSummary[] }>('export-list')).requests ?? []); } catch { /* shown on the next action */ }
    try { setActivity((await directory<{ entries: AuditEntry[] }>('audit', { limit: 20 })).entries ?? []); } catch { /* idem */ }
  }, [directory]);

  const load = useCallback(async () => {
    setBusy(true);
    setError(null);
    setNotEnabled(false);
    const r = await fetch(`/connect/admin/organizations?app=${encodeURIComponent(app)}`, { headers: { authorization: `Bearer ${token}` } }).catch(() => null);
    const j = (await r?.json().catch(() => null)) as (OrganizationsView & { error?: string }) | null;
    setBusy(false);
    if (r?.ok && j) {
      setView(j);
      if (j.masked) void loadSide();
    } else {
      setView(null);
      if (r?.status === 409) setNotEnabled(true);
      else setError(j?.error ?? (r ? `HTTP ${r.status}` : 'The Home did not answer.'));
    }
  }, [app, token, loadSide]);
  useEffect(() => { void load(); }, [load]);

  const masked = view?.masked === true;
  const accountsMode = view?.rows === 'accounts';
  const base = useMemo(() => (view?.orgs ?? []).filter((o) => showTest || !o.test), [view, showTest]);
  const types = useMemo(() => {
    const m = new Map<string, { label: string; count: number }>();
    for (const o of base) {
      const k = typeKey(o);
      const label = k === 'none' ? 'No type yet' : k === 'other' ? 'Other' : o.type?.label ?? k;
      m.set(k, { label, count: (m.get(k)?.count ?? 0) + 1 });
    }
    return [...m.entries()].sort(([a, x], [b, y]) => {
      const rank = (k: string) => (k === 'other' ? 1 : k === 'none' ? 2 : 0);
      return rank(a) - rank(b) || y.count - x.count || x.label.localeCompare(y.label);
    });
  }, [base]);
  const shown = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return base.filter((o) => {
      if (type !== 'all' && typeKey(o) !== type) return false;
      if (noEmail && reachable(o)) return false;
      if (!needle) return true;
      return [o.name, o.org, typeText(o), o.orgContact?.email ?? '', ...(o.methods ?? []), ...o.contacts.flatMap((c) => [c.email ?? '', c.account])].some((s) => s.toLowerCase().includes(needle));
    });
  }, [base, q, type, noEmail]);

  const fileName = (forApp = app) =>
    forApp === 'all-accounts'
      ? `gcid-accounts-${new Date().toISOString().slice(0, 10)}.csv`
      : `${view?.apps.find((x) => x.id === forApp)?.label ?? forApp}-organizations-${new Date().toISOString().slice(0, 10)}.csv`;

  const run = async (fn: () => Promise<void>) => {
    setError(null);
    setNote(null);
    try { await fn(); } catch (e) { setError(e instanceof Error ? e.message : String(e)); }
  };

  const reveal = (account: string) => run(async () => {
    const r = await directory<{ email: string | null }>('reveal', { account });
    setRevealed((s) => ({ ...s, [account]: r.email }));
    void loadSide();
  });

  const requestExport = () => run(async () => {
    const why = window.prompt('Why is this export needed? (The second admin sees this.)', '') ?? null;
    if (why === null) return;
    const accounts = [...new Set(shown.flatMap((o) => [o.org, ...o.contacts.map((c) => c.account)]))];
    await directory('export-request', { app, accounts, note: why });
    setNote(`Export requested for ${shown.length} ${accountsMode ? 'account' : 'organization'}${shown.length === 1 ? '' : 's'}. Another admin has to approve it before you can download it.`);
    void loadSide();
  });

  const decide = (id: string, action: 'export-approve' | 'export-deny') => run(async () => {
    await directory(action, { id });
    void loadSide();
  });

  const fetchExport = (r: ExportSummary) => run(async () => {
    const got = await directory<{ rows: { account: string; email: string | null }[] }>('export-fetch', { id: r.id });
    if (r.app === 'all-accounts') {
      // Built from the approved rows themselves, so it is right whichever list is on screen.
      const methods = new Map((view?.rows === 'accounts' ? view.orgs : []).map((o) => [o.org, o.methods ?? []]));
      save(fileName('all-accounts'), accountsCsv(got.rows, methods));
      void loadSide();
      return;
    }
    if (r.app !== app) throw new Error(`This export is for ${view?.apps.find((x) => x.id === r.app)?.label ?? r.app}. Switch the list to it first, then download.`);
    const emails = new Map(got.rows.map((x) => [x.account, x.email]));
    const rows = (view?.orgs ?? []).filter((o) => emails.has(o.org) || o.contacts.some((c) => emails.has(c.account)));
    save(fileName(), csv(rows, emails));
    void loadSide();
  });

  const enable = () => run(async () => {
    const me2 = await fetch('/connect/admin/me', { headers: { authorization: `Bearer ${token}` } }).then((r) => r.json()).catch(() => ({})) as { operatorOrg?: string };
    if (!me2.operatorOrg) throw new Error('No operator organization is configured for this Home.');
    if (!INTERACTIONS_SERVICE_SA) throw new Error('This Home has no interactions service configured.');
    const profile = await fetchProfile(token);
    const sign = await signHashFor(resolveVia(profile?.credential, session.via), me2.operatorOrg as Address, { token });
    const delegation = await issueOperatorDirectoryDelegation(me2.operatorOrg as Address, INTERACTIONS_SERVICE_SA, MCP_SERVER_ID, sign);
    await directory('enable', { delegation: { ...delegation, salt: delegation.salt.toString() } });
    setNote('The operator directory is enabled.');
    await load();
  });

  const importOld = () => run(async () => {
    let imported = 0;
    let found = 0;
    let offset: number | undefined = 0;
    while (offset !== undefined) {
      const r: { imported: number; found: number; next?: number } = await directory('import', { offset });
      imported += r.imported;
      found = r.found;
      offset = r.next;
      setNote(`Importing… ${imported} so far of ${found}.`);
    }
    setNote(`Imported ${imported} addresses from the old directory (${found} found; ones already in the operator directory were kept).`);
    void loadSide();
  });

  const emailCell = (account: string, value: string | null | undefined) => {
    if (!value) return null;
    if (!masked) return <a href={`mailto:${value}`}>{value}</a>;
    if (account in revealed) return revealed[account] ? <a href={`mailto:${revealed[account]}`}>{revealed[account]}</a> : <Meta>not on file</Meta>;
    return (
      <>
        <span className="admin-orgs__masked">{value}</span>{' '}
        <button type="button" className="admin-orgs__reveal" onClick={() => void reveal(account)} data-testid={`admin-orgs-reveal-${account.slice(2, 10)}`}>Show</button>
      </>
    );
  };

  const withEmail = base.filter(reachable).length;
  const testCount = (view?.orgs ?? []).filter((o) => o.test).length;
  const pending = exportsList.filter((r) => r.status === 'pending' || r.status === 'approved');

  return (
    <>
      <Toolbar>
        <label className="admin-orgs__app">
          <span>App</span>
          <select value={app} onChange={(e) => { setApp(e.target.value); setType('all'); setNoEmail(false); }} data-testid="admin-orgs-app">
            {(view?.apps ?? [{ id: 'gather-app', label: 'Gather' }]).map((a) => <option key={a.id} value={a.id}>{a.label}</option>)}
          </select>
        </label>
        <div className="admin-orgs__search">
          <SearchInput value={q} onChange={(e) => setQ(e.target.value)} placeholder={accountsMode ? 'Search address, email or sign-in' : 'Search name, type or address'} aria-label={accountsMode ? 'Search accounts' : 'Search organizations'} data-testid="admin-orgs-q" />
        </div>
        {masked ? (
          <Button size="sm" onClick={() => void requestExport()} disabled={!shown.length} data-testid="admin-orgs-export-request">Request export</Button>
        ) : (
          <Button size="sm" onClick={() => save(fileName(), csv(shown))} disabled={!shown.length || !view} data-testid="admin-orgs-csv">Download CSV</Button>
        )}
        <Button size="sm" onClick={() => void load()} disabled={busy}>{busy ? 'Loading…' : 'Refresh'}</Button>
      </Toolbar>
      {error && <ErrorNote>{error}</ErrorNote>}
      {note && <Note>{note}</Note>}
      {notEnabled && (
        <Empty title="The operator directory is not enabled yet">
          Contact emails live in the operator organization&rsquo;s vault. Enabling signs a grant, as the operator organization, that lets the
          directory service keep them there and nothing else.{' '}
          <Button size="sm" onClick={() => void enable()} data-testid="admin-orgs-enable">Enable the operator directory</Button>
        </Empty>
      )}
      {view === undefined && !notEnabled && <SkeletonRows rows={5} lead />}
      {view === null && !error && !notEnabled && <Empty title="Organizations are unavailable" />}
      {view && (
        <>
          {accountsMode ? (
            <Stats>
              <Stat label="accounts" value={base.length.toLocaleString()} testId="admin-orgs-total" />
              <Stat label="with a sign-in email" value={withEmail.toLocaleString()} />
              <Stat label="no email on file" value={(base.length - withEmail).toLocaleString()} />
            </Stats>
          ) : (
            <Stats>
              <Stat label="organizations" value={base.length.toLocaleString()} testId="admin-orgs-total" />
              <Stat label="with a contact email" value={withEmail.toLocaleString()} />
              <Stat label="no type yet" value={(types.find(([k]) => k === 'none')?.[1].count ?? 0).toLocaleString()} />
            </Stats>
          )}
          {masked && pending.length > 0 && (
            <Section title="Export requests" count={pending.length} testId="admin-orgs-exports">
              <div className="admin-orgs__scroll">
                <table className="admin-orgs__table">
                  <thead><tr><th>Requested</th><th>By</th><th>Rows</th><th>Why</th><th>Status</th><th /></tr></thead>
                  <tbody>
                    {pending.map((r) => (
                      <tr key={r.id} data-testid={`admin-orgs-export-${r.id.slice(0, 8)}`}>
                        <td>{when(r.requestedAt)}</td>
                        <td><Mono title={r.requestedBy}>{r.requestedBy === me ? 'you' : short(r.requestedBy)}</Mono></td>
                        <td>{r.count}{r.app === 'all-accounts' ? <> <Meta>accounts</Meta></> : null}</td>
                        <td>{r.note || <Meta>—</Meta>}</td>
                        <td>{r.status === 'pending' ? 'waiting for a second admin' : `approved by ${r.approvedBy === me ? 'you' : short(r.approvedBy ?? '')}`}</td>
                        <td>
                          {r.status === 'pending' && r.requestedBy !== me && (
                            <>
                              <Button size="sm" onClick={() => void decide(r.id, 'export-approve')}>Approve</Button>{' '}
                              <Button size="sm" variant="ghost" onClick={() => void decide(r.id, 'export-deny')}>Deny</Button>
                            </>
                          )}
                          {r.status === 'approved' && r.requestedBy === me && <Button size="sm" onClick={() => void fetchExport(r)}>Download</Button>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <Note>An export needs a second admin. Once approved, the admin who requested it can download it once, within 30 minutes.</Note>
            </Section>
          )}
          <div className="admin-orgs__filters" role="group" aria-label={accountsMode ? 'Filter accounts' : 'Filter by type'}>
            {!accountsMode && <FilterChip active={type === 'all'} count={base.length} onClick={() => setType('all')}>All types</FilterChip>}
            {!accountsMode && types.map(([k, t]) => (
              <FilterChip key={k} active={type === k} count={t.count} onClick={() => setType(type === k ? 'all' : k)} data-testid={`admin-orgs-type-${k === 'none' || k === 'other' ? k : k.split('-').pop()}`}>{t.label}</FilterChip>
            ))}
            {!accountsMode && <span className="admin-orgs__sep" aria-hidden />}
            <FilterChip active={noEmail} onClick={() => setNoEmail(!noEmail)}>{accountsMode ? 'No email on file' : 'No contact email'}</FilterChip>
            {testCount > 0 && <FilterChip active={showTest} count={testCount} onClick={() => setShowTest(!showTest)}>Show test accounts</FilterChip>}
          </div>
          {!view.emails && <Note>The contact directory is not switched on for this Home (no key configured), so emails are not shown.</Note>}
          {accountsMode ? (
          <Section title="Accounts" count={shown.length} aside={<Meta>as of {when(view.asOf)}</Meta>} testId="admin-orgs">
            {shown.length === 0 ? (
              <Note>{base.length === 0 ? 'No accounts yet.' : 'No accounts match.'}</Note>
            ) : (
              <div className="admin-orgs__scroll">
                <table className="admin-orgs__table">
                  <thead><tr><th>Account</th><th>Signs in with</th><th>Email</th></tr></thead>
                  <tbody>
                    {shown.map((o) => (
                      <tr key={o.org} data-testid={`admin-accounts-row-${o.org.slice(2, 10)}`}>
                        <td><Mono title={o.org}>{short(o.org)}</Mono>{o.test && <> <Meta>test</Meta></>}</td>
                        <td>{(o.methods ?? []).map((m) => METHOD_WORDS[m] ?? m).join(', ') || '—'}</td>
                        <td>{o.orgContact ? emailCell(o.org, o.orgContact.email) : <Meta>No email on file</Meta>}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Section>
          ) : (
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
                          {o.handle && <div><Meta>{o.handle}</Meta></div>}
                          <div><Mono title={o.org}>{short(o.org)}</Mono></div>
                        </td>
                        <td>
                          {!o.type ? <Meta>No type yet</Meta> : o.type.iri === null ? <>Other <Meta>“{o.type.other}”</Meta></> : o.type.label}
                        </td>
                        <td>
                          {o.orgContact ? (
                            <div className="admin-orgs__org-contact">
                              {emailCell(o.org, o.orgContact.email)}
                              <div><Meta>{o.orgContact.changed ? `organization contact · confirmed ${day(o.orgContact.verifiedAt)}` : 'organization contact · from its creator'}</Meta></div>
                            </div>
                          ) : (
                            <div><Meta>No organization contact yet</Meta></div>
                          )}
                          {o.contacts.length > 0 && <div className="admin-orgs__managed"><Meta>Managed by</Meta></div>}
                          {o.contacts.length === 0 && <Meta>No manager found</Meta>}
                          {o.contacts.map((c) => (
                            <div key={c.account}>
                              {c.email ? emailCell(c.account, c.email) : <span title={c.account}><Meta>No email on file ({short(c.account)})</Meta></span>}
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
          )}
          <Note>
            {accountsMode ? (
              <>Every GCID account, whatever app it came through, at the email it signs in with. People who sign in only with a passkey, phone or Google have none on file.{' '}</>
            ) : (
              <>
                Each organization&rsquo;s contact starts as the email of the person who created it, and changes only when someone who manages it
                confirms a new address with a code. Below it are the people who manage it, at the email they sign in with; members are counted, not
                listed.{' '}
              </>
            )}
            {masked
              ? 'Addresses are masked. "Show" reveals one and is recorded; a full export needs a second admin to approve it. Every view, reveal and export is recorded in the operator organization’s vault.'
              : 'Every time this list is opened is recorded with your account and the time.'}
          </Note>
          {masked && activity.length > 0 && (
            <Section title="Recent directory activity" testId="admin-orgs-activity">
              <Note>
                {activity.map((e) => `${e.by === me ? 'You' : short(e.by)} ${AUDIT_WORDS[e.kind] ?? e.kind}${e.accounts !== undefined ? ` (${e.accounts})` : ''} · ${when(e.at)}`).join('  ·  ')}
              </Note>
            </Section>
          )}
          {masked && (
            <Note>
              Moving from the old directory? <button type="button" className="admin-orgs__reveal" onClick={() => void importOld()} data-testid="admin-orgs-import">Import the old directory</button> (once; addresses already in the operator directory are kept).
            </Note>
          )}
          {!masked && view.views.length > 0 && (
            <Note>
              Recently opened by: {view.views.map((v) => `${short(v.by)} ${when(v.at)}`).join(' · ')}
            </Note>
          )}
        </>
      )}
    </>
  );
}
