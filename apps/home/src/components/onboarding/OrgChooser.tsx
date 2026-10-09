'use client';
import { WorkingBar } from './WorkingBar';
// Home-side org chooser for an org-create enroll that arrives WITHOUT a preselected org
// (`org_base` / `existing_org` absent): the person picks an organization they belong to
// (membership, or a stewarded org created for this request's purpose) — or names a new
// one to deploy. Unrelated stewarded orgs are not offered.
//
// Selection deliberately lives HERE, not at the relying app: a relying app's related-orgs
// view is scoped to the orgs it already holds a grant for (spec 246), so it can never
// offer an org created elsewhere (another app, the home portal). The member's own home
// session can — person↔org links are private vault credentials the home reads (ADR-0025).
//
// Listing related orgs needs a home session token. Without one (e.g. a passkey member
// whose `ap_sso` cookie is gone) we say so explicitly and offer create-new only — a
// visible degradation, never a silent empty list (ADR-0013: the missing session is
// surfaced, not swallowed).
import { useEffect, useMemo, useRef, useState } from 'react';
import type { Address } from '@agenticprimitives/types';
import { listManagedAgents } from '../../connect-client';
import { humanizeOrgName, shortAppHost, toOrgLabel } from './org-chooser-label';
import { canGrantAsOrg, eligibleConnectOrgs } from './org-chooser-eligible';

export { shortAppHost, toOrgLabel } from './org-chooser-label';

export interface OrgChoice {
  /** Set when the person picked an organization they already belong to (no deploy). */
  existingOrg?: Address;
  /** The org's display name (existing) or the new org's label to claim. */
  orgName: string;
  /** True when they can sign as the org. Members connect as themselves with this org as context. */
  asSteward?: boolean;
}

const orgHue = (s: string): number => {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) >>> 0;
  return h % 360;
};

function OrgAvatar({ name, plus }: { name: string; plus?: boolean }) {
  return (
    <span
      aria-hidden
      className={`org-chooser-avatar${plus ? ' plus' : ''}`}
      style={plus ? undefined : { background: `hsl(${orgHue(name)}, 45%, 48%)` }}
    >
      {plus ? '+' : (name.replace(/\..*$/, '').slice(0, 1).toUpperCase() || '?')}
    </span>
  );
}

export function OrgChooser({
  token,
  appHost,
  appName,
  purpose,
  defaultName,
  hideHandles = false,
  onChoose,
  onDecline,
}: {
  /** Home-session bearer (aud = home). Absent → create-new only, with the reason shown. */
  token?: string;
  appHost: string;
  /** The app's REGISTERED friendly name (e.g. "Gather27"). Without it the heading falls back to
   *  the hostname's first label ("gather27-web") — a deployment slug no member recognizes. */
  appName?: string;
  /** `org_purpose` from the enroll. When set, stewarded orgs for other purposes are hidden. */
  purpose?: string;
  /** `org_base` from the enroll — the name the person typed AT THE APP. With no eligible
   *  existing org, the chooser never renders: it auto-creates under this name (the seamless
   *  first-host path). With eligible orgs it prefills create-new, so picking the existing
   *  org — instead of silently minting a duplicate — is one visible tap. */
  defaultName?: string;
  /** Never show the org's handle (`<slug>.impact`) — for a client whose people never see one (`consent.hideIdentifiers`). */
  hideHandles?: boolean;
  onChoose: (choice: OrgChoice) => void;
  onDecline: () => void;
}) {
  // null = loading; [] = none (or no session to list with).
  const [orgs, setOrgs] = useState<Array<{ agent: Address; name: string; asSteward: boolean }> | null>(token ? null : []);
  const [selected, setSelected] = useState<'new' | Address>('new');
  const [name, setName] = useState(defaultName ?? '');
  const [query, setQuery] = useState('');
  const [err, setErr] = useState('');
  const autoRan = useRef(false);

  useEffect(() => {
    if (!token) return;
    let cancelled = false;
    listManagedAgents(token)
      .then((agents) => {
        if (cancelled) return;
        const listed = eligibleConnectOrgs(agents, { purpose }).map((a) => ({
          agent: a.agent,
          name: a.name,
          asSteward: canGrantAsOrg(a),
        }));
        setOrgs(listed);
        // Stay on "create new" — this screen is the org-create ceremony. Auto-picking the
        // first stewarded org hid the create action behind a long list and pre-committed
        // the member to an existing org they did not choose.
      })
      .catch(() => { if (!cancelled) setOrgs([]); });
    return () => { cancelled = true; };
  }, [token, purpose]);

  // The app already named the org and the person has no eligible existing one — nothing to
  // choose. Create under that name without rendering a screen (one Home window, no extra step).
  useEffect(() => {
    if (autoRan.current || orgs === null || orgs.length > 0) return;
    const slugged = toOrgLabel(defaultName ?? '');
    if (slugged.length < 3) return;
    autoRan.current = true;
    onChoose({ orgName: slugged });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [orgs, defaultName]);

  const filtered = useMemo(() => {
    const list = orgs ?? [];
    const q = query.trim().toLowerCase();
    if (!q) return list;
    return list.filter((o) => o.name.toLowerCase().includes(q) || o.agent.toLowerCase().includes(q));
  }, [orgs, query]);

  // Keep the spinner up while the auto-create path decides — never flash a chooser that is
  // about to answer itself.
  if (orgs === null || (orgs.length === 0 && toOrgLabel(defaultName ?? '').length >= 3)) {
    return (
      <div className="onboarding-busy">
        <WorkingBar />
        <span className="spinner spinner-lg" role="status" aria-label="Loading your organizations" />
        <p className="onboarding-busy-msg">Finding organizations you belong to…</p>
      </div>
    );
  }

  const chosen = selected !== 'new' ? orgs.find((o) => o.agent.toLowerCase() === selected.toLowerCase()) : undefined;
  const slug = toOrgLabel(name);
  const host = appName ?? shortAppHost(appHost);
  // The name the person typed AT THE APP may already be an org they belong to — showing a
  // prefilled "create" AND the same org in the list, with nothing saying which to pick, is how
  // duplicates get minted. Surface the likely match instead.
  const wantedSlug = toOrgLabel(defaultName ?? '');
  const likelyMatch =
    wantedSlug.length >= 3
      ? orgs.find((o) => toOrgLabel(o.name.replace(/\.impact$/i, '')) === wantedSlug)
      : undefined;

  const go = () => {
    if (chosen) return onChoose({ existingOrg: chosen.agent, orgName: chosen.name, asSteward: chosen.asSteward });
    if (slug.length < 3) { setErr('Give the new organization a name of at least 3 letters or numbers.'); return; }
    onChoose({ orgName: slug });
  };

  const pickNew = () => { setSelected('new'); setErr(''); };
  const pickOrg = (agent: Address) => { setSelected(agent); setErr(''); };

  return (
    <div className="org-chooser">
      <p className="onboarding-hint">
        Almost there — {host} sent you here to pick the organization it will work with.
      </p>
      <h1 className="onboarding-h1">Choose your organization</h1>
      <p className="onboarding-sub">
        {host} will only be able to read what this organization shares with it. It can&apos;t make
        changes, reach your other organizations, or act on your behalf — and you can disconnect it
        any time from your Impact home.
      </p>
      {!token && (
        <p className="onboarding-hint">
          We couldn&apos;t load the organizations you belong to right now — you can still create a
          new one below.
        </p>
      )}

      <label className={`org-chooser-row create${selected === 'new' ? ' on' : ''}`}>
        <input type="radio" name="org-choice" className="org-chooser-sr" checked={selected === 'new'} onChange={pickNew} />
        <OrgAvatar name="+" plus />
        <span className="org-chooser-copy">
          <span className="org-chooser-name">Create a new organization</span>
          <span className="org-chooser-meta">You&apos;ll be its first admin — you keep full control</span>
        </span>
        {selected === 'new' && <span aria-hidden className="org-chooser-check">✓</span>}
      </label>
      {selected === 'new' && (
        <input
          className="onboarding-input"
          placeholder="New organization name"
          value={name}
          autoFocus
          onChange={(e) => { setName(e.target.value); setErr(''); }}
          onKeyDown={(e) => { if (e.key === 'Enter') go(); }}
        />
      )}
      {selected === 'new' && likelyMatch && (
        <p className="onboarding-hint">
          It looks like you may already have this organization —{' '}
          <strong>{humanizeOrgName(likelyMatch.name)}</strong> is in your list below. If that&apos;s
          it, select it there instead of creating it again.
        </p>
      )}
      {!hideHandles && selected === 'new' && slug && slug !== name.trim() && (
        <p className="onboarding-hint">Its web address will be <strong>{slug}.impact</strong>.</p>
      )}

      {orgs.length > 0 && (
        <>
          <p className="org-chooser-section">
            Or use one you belong to
            <span className="org-chooser-count">{orgs.length}</span>
          </p>
          {orgs.length > 5 && (
            <input
              className="onboarding-input org-chooser-filter"
              type="search"
              placeholder="Filter organizations"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              aria-label="Filter organizations you belong to"
            />
          )}
          <div className="org-chooser-list" role="listbox" aria-label="Organizations you belong to">
            {filtered.length === 0 && (
              <p className="onboarding-hint">No organization you belong to matches that filter.</p>
            )}
            {filtered.map((o) => {
              const on = selected.toLowerCase() === o.agent.toLowerCase();
              return (
                <label key={o.agent} className={`org-chooser-row${on ? ' on' : ''}`}>
                  <input type="radio" name="org-choice" className="org-chooser-sr" checked={on} onChange={() => pickOrg(o.agent)} />
                  <OrgAvatar name={o.name} />
                  <span className="org-chooser-copy">
                    <span className="org-chooser-name">{humanizeOrgName(o.name)}</span>
                    <span className="org-chooser-meta">
                      {o.asSteward ? 'You manage this organization' : 'You’re a member'}
                    </span>
                  </span>
                  {on && <span aria-hidden className="org-chooser-check">✓</span>}
                </label>
              );
            })}
          </div>
        </>
      )}

      {err && <p className="onboarding-hint taken">{err}</p>}
      <button className="btn-primary" onClick={go}>
        {chosen
          ? `Continue with ${humanizeOrgName(chosen.name)}`
          : name.trim()
            ? `Create ${name.trim()}`
            : 'Create organization'}
      </button>
      <button className="btn-ghost onboarding-secondary" onClick={onDecline}>Go back to {host}</button>
    </div>
  );
}
