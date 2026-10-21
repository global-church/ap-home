/**
 * spec 348 — one nav shape for every agent class.
 *
 * WHAT THIS PINS, and why each case exists:
 *
 * The three navs used to disagree about where the same thing lived — Trust graph was in Manage for an
 * org and Discovery for a person, a service had no Library because nobody wired one, and `Manage` had
 * become the bucket for nine unrelated items. The shape is the contract now: a class may LACK a whole
 * area, but it may never put a shared item somewhere else.
 *
 * The per-item exceptions below are deliberate and each is grounded in a surface that does or does not
 * exist — never in making a list shorter. If one of them starts failing because the surface was built,
 * the fix is to delete the exception, not to loosen the test.
 */
import { describe, it, expect } from 'vitest';
import { buildNav, buildSettingsPane, buildUserMenu, withAdminNav, paneGroups, stewardshipPane, securityPane, connectedPane, developerPane, type NavGroup } from './nav';
import { whitelabel } from '../../whitelabel/config';

const ORG = '0xe26157068af46629691e2ab19726bf61476e6b6c';
const SVC = '0x3d653cbab0c99b1513439758eb2eac2039caa6e1';
const PERSON = { kind: 'person' } as const;
const ORG_SCOPE = { kind: 'org', org: ORG } as const;
const SVC_SCOPE = { kind: 'service', agent: SVC } as const;

const labels = (g: NavGroup[]): string[] => g.flatMap((x) => x.items.map((i) => i.label));
const TOP = ['Today', 'Messages', 'Activities', 'Library'];

describe('the top band is the same four for every class', () => {
  for (const [name, scope] of [['person', PERSON], ['org', ORG_SCOPE], ['service', SVC_SCOPE]] as const) {
    it(`${name}: Today · Messages · Activities · Library, in that order, and none of them a pane`, () => {
      const first = buildNav(whitelabel, {}, scope)[0]!;
      expect(first.items.map((i) => i.label)).toEqual(TOP);
      expect(first.items.some((i) => i.opensPane)).toBe(false);
    });
  }
});

describe('areas are present or absent as a whole — never rearranged', () => {
  it('Stewardship is for agents that steward: person and org, not a service', () => {
    expect(labels(buildNav(whitelabel, {}, PERSON))).toContain('Stewardship');
    expect(labels(buildNav(whitelabel, {}, ORG_SCOPE))).toContain('Stewardship');
    expect(labels(buildNav(whitelabel, {}, SVC_SCOPE))).not.toContain('Stewardship');
    expect(paneGroups('stewardship', SVC_SCOPE)).toEqual([]);
  });

  it('Records and Attestations are plain rows for every class that has them', () => {
    for (const scope of [PERSON, ORG_SCOPE, SVC_SCOPE]) expect(labels(buildNav(whitelabel, {}, scope))).toContain('Records');
  });

  it('Work is a main-nav item for person and org, absent for a service', () => {
    expect(labels(buildNav(whitelabel, {}, PERSON))).toContain('Work');
    expect(labels(buildNav(whitelabel, {}, ORG_SCOPE))).toContain('Work');
    expect(labels(buildNav(whitelabel, {}, SVC_SCOPE))).not.toContain('Work');
  });
});

describe('ONE grammar for every second level: a row that opens a pane', () => {
  // The first build had two — collapsible areas AND a pane — so the same small-caps heading meant both
  // "click to expand here" and "a label you cannot click". Now: exactly the rows that open panes carry
  // `opensPane`, nothing collapses in place, and no group in the main nav has a heading at all.
  const items = (scope: Parameters<typeof buildNav>[2]) => buildNav(whitelabel, {}, scope).flatMap((g) => g.items);

  it('exactly Stewardship and Settings open panes', () => {
    expect(items(PERSON).filter((i) => i.opensPane).map((i) => i.label)).toEqual(['Stewardship', 'Settings']);
    expect(items(SVC_SCOPE).filter((i) => i.opensPane).map((i) => i.label)).toEqual(['Settings']);
  });

  it('a pane row points INTO its pane, so clicking it lands somewhere real', () => {
    for (const scope of [PERSON, ORG_SCOPE]) {
      const row = items(scope).find((i) => i.opensPane === 'stewardship')!;
      const first = paneGroups('stewardship', scope)[0]!.items[0]!;
      expect(row.href).toBe(first.href);
    }
  });

  it('no main-nav group carries a heading — small-caps is a pane label and nothing else', () => {
    for (const scope of [PERSON, ORG_SCOPE, SVC_SCOPE]) {
      expect(buildNav(whitelabel, {}, scope).filter((g) => g.heading)).toEqual([]);
    }
  });

  it('Stewardship sits directly above Settings — the two panes are neighbours', () => {
    for (const scope of [PERSON, ORG_SCOPE]) {
      const l = items(scope).map((i) => i.label);
      expect(l.indexOf('Settings') - l.indexOf('Stewardship')).toBe(1);
    }
  });
});

describe('the shape after the 2026-08-31 design review', () => {
  it('Settings is LAST — it is the door you take to change the thing you were working in', () => {
    for (const scope of [PERSON, ORG_SCOPE, SVC_SCOPE]) {
      const g = buildNav(whitelabel, {}, scope);
      // (a non-person workspace ends with the "Back to your home" exit)
      const meaningful = g.filter((x) => !x.isExit);
      expect(meaningful[meaningful.length - 1]!.items.map((i) => i.label)).toEqual(['Settings']);
    }
  });

  it('carries exactly ONE region divider — more than one carries no information', () => {
    for (const scope of [PERSON, ORG_SCOPE, SVC_SCOPE]) {
      expect(buildNav(whitelabel, {}, scope).filter((g) => g.startsRegion)).toHaveLength(1);
    }
  });

  it('no group heads the nav with the workspace NAME — it uppercased a user-supplied string', () => {
    // It also existed for org/service and not person, so every row shifted when you switched context.
    const org = buildNav(whitelabel, {}, ORG_SCOPE, 'steward', 'alice-home-church');
    expect(org.some((g) => (g.heading ?? '').includes('alice'))).toBe(false);
  });

  it('a one-item area names itself, so the row reads as the destination', () => {
    // Records and Attestations hold one item each today; the sidebar folds them to plain rows, so the
    // item has to carry the area's noun rather than a disambiguator for a heading that is not rendered.
    const l = labels(buildNav(whitelabel, {}, PERSON));
    expect(l).toContain('Records');
    expect(l).toContain('Attestations');
    expect(l).not.toContain('All records');
    expect(l).not.toContain('Signed statements');
  });
});

describe('a nameless agent shows what it cannot do yet, and why', () => {
  const pane = (hasName: boolean) => buildSettingsPane(PERSON, 'steward', hasName);
  const item = (hasName: boolean, label: string) =>
    pane(hasName).flatMap((g) => g.items).find((i) => i.label === label)!;

  it('Agent Card and Registry wait on a name — and say so', () => {
    // Trust graph is no longer in this pane, so it is no longer this pane's job to gate it.
    for (const label of ['Agent Card', 'Registry']) {
      expect(item(false, label).disabledReason).toContain('name');
      expect(item(true, label).disabledReason).toBeUndefined();
    }
  });

  it('Naming and Profile stay open — naming it is the way out', () => {
    expect(item(false, 'Naming').disabledReason).toBeUndefined();
    expect(item(false, 'Profile').disabledReason).toBeUndefined();
  });

  it('Visibility stays open: an invitation is how someone reaches a nameless agent', () => {
    // spec 338 — naming, listing, resolution and inbound are four INDEPENDENT choices, so lacking the
    // first must not remove the others.
    expect(item(false, 'Visibility').disabledReason).toBeUndefined();
  });

  it('nothing is HIDDEN by being nameless — the pane keeps its shape', () => {
    expect(pane(false).flatMap((g) => g.items).map((i) => i.label))
      .toEqual(pane(true).flatMap((g) => g.items).map((i) => i.label));
  });

  it('Reachability stays available while nameless — an invitation is how you reach an unnamed agent', () => {
    // spec 338: named · listed · resolvable · inbound are four INDEPENDENT choices. Trust graph left
    // Settings entirely (it is a view of what others said, not a setting), so the old "Visibility sits
    // after Trust graph" ordering no longer has two things to order.
    const nameless = pane(false);
    const reach = nameless.find((g) => g.heading === 'Reachability')?.items.map((i) => i.label) ?? [];
    expect(reach).toEqual(['Visibility', 'Invitations issued']);
    for (const i of nameless.flatMap((g) => g.items).filter((x) => x.label === 'Visibility')) {
      expect(i.disabledReason, 'reaching a nameless agent is the point of an invitation').toBeUndefined();
    }
  });
});

describe('Members is a main-nav item for workspaces that coordinate people', () => {
  const labelsFor = (scope: Parameters<typeof buildNav>[2], hasMembers: boolean) =>
    buildNav(whitelabel, {}, scope, 'steward', undefined, hasMembers).flatMap((g) => g.items).map((i) => i.label);

  it('an organization has one', () => {
    expect(labelsFor(ORG_SCOPE, true)).toContain('Members');
  });

  it('a service agent has one only when it coordinates people', () => {
    // A workspace does; a treasury or a registry does not, and an always-empty roster teaches nothing.
    expect(labelsFor(SVC_SCOPE, true)).toContain('Members');
    expect(labelsFor(SVC_SCOPE, false)).not.toContain('Members');
  });

  it('a person never has one — a person is not a workspace with a roster', () => {
    expect(labelsFor(PERSON, true)).not.toContain('Members');
  });
});

describe('account surfaces left the workspace nav for the user menu', () => {
  it('no class shows Security, Connected, Your apps or Network in the left nav', () => {
    for (const scope of [PERSON, ORG_SCOPE, SVC_SCOPE]) {
      const l = labels(buildNav(whitelabel, {}, scope));
      for (const gone of ['Security', 'Connected', 'Your apps', 'Network']) expect(l).not.toContain(gone);
    }
  });

  it('and they are all reachable from the user menu instead', () => {
    const menu = buildUserMenu(whitelabel).map((i) => i.label);
    expect(menu).toContain('Network');
    expect(menu).toContain('Your profile');
  });
});

describe('the Settings pane', () => {
  const groups = (scope: Parameters<typeof buildSettingsPane>[0]) => buildSettingsPane(scope).map((g) => g.heading);
  const items = (scope: Parameters<typeof buildSettingsPane>[0]) =>
    buildSettingsPane(scope).flatMap((g) => g.items.map((i) => i.label));

  it('is grouped the same way, in the same order, for every class that has the group', () => {
    // Six groups, each answering ONE question: who it is · what it can do · how it is found · whether
    // it can be reached · how it acts · who may act through it.
    //
    // Capabilities is its OWN group, not a row under Discovery. It is the record every other surface
    // projects from (ADR-0051) — the card advertises a curated subset, the registry ranks the ids it
    // publishes, ARD restates them — and filing the source under one of its consumers is part of how
    // the Card Studio grew a rival capability editor.
    for (const scope of [ORG_SCOPE, SVC_SCOPE]) {
      expect(groups(scope)).toEqual(['Identity', 'Capabilities', 'Discovery', 'Behaviour', 'Authority']);
    }
    // A person has no Authority group, and that is the honest outcome rather than an empty heading
    // (§5): they have no members, no lifecycle status, and their own access — credentials and the
    // delegations they hold — is Security, in the user menu, because it is about the person and not
    // about an agent in a workspace. Reachability is person-only for the mirror-image reason.
    expect(groups(PERSON)).toEqual(['Identity', 'Capabilities', 'Discovery', 'Reachability', 'Behaviour']);
  });

  it('carries the shared identity items everywhere', () => {
    for (const scope of [PERSON, ORG_SCOPE, SVC_SCOPE]) {
      // 'Capabilities' is what the agent can DO; 'Playbook' is the SKILL.md procedural package. They were
      // both called some form of "skill" before ADR-0051, which is exactly the collision being removed —
      // so this list asserts both names survive, separately.
      // Trust graph is NOT here any more — it moved to the main nav beside Attestations, because
      // nothing on it is configured; it shows what other agents have said.
      for (const item of ['Profile', 'Naming', 'Agent Card', 'Registry', 'Capabilities', 'Playbook']) {
        expect(items(scope)).toContain(item);
      }
    }
  });

  it('Membership is org-only, and is the MANAGEMENT surface — not the roster', () => {
    // "Who is here" is a main-nav item; this is where a steward decides who gets in. Two questions, two
    // places: looking a colleague up should not land you among pending applications.
    expect(items(ORG_SCOPE)).toContain('Membership');
    expect(items(ORG_SCOPE)).not.toContain('Members');
    expect(items(PERSON)).not.toContain('Membership');
    expect(items(SVC_SCOPE)).not.toContain('Membership');
  });

  it('a service has no Ask: its Playbook IS what it answers as, so Ask would be a second name for one page', () => {
    expect(items(SVC_SCOPE)).not.toContain('Ask');
    expect(items(PERSON)).toContain('Ask');
    expect(items(ORG_SCOPE)).toContain('Ask');
  });

  it('only a person has Discussion replies — an org’s discussion behaviour is its assistant', () => {
    expect(items(PERSON)).toContain('Discussion replies');
    expect(items(ORG_SCOPE)).not.toContain('Discussion replies');
  });

  it('never offers "Discussions" — that word is the top band, where you take part', () => {
    for (const scope of [PERSON, ORG_SCOPE, SVC_SCOPE]) expect(items(scope)).not.toContain('Discussions');
  });

  it('Status replaces the org lifecycle page’s old name, which now names the pane', () => {
    expect(items(ORG_SCOPE)).toContain('Status');
    expect(items(ORG_SCOPE)).not.toContain('Settings');
  });
});

describe('membership is not widened by any of this (spec 318)', () => {
  it('an org member gets participation only — no Settings, no Stewardship, no Records', () => {
    const l = labels(buildNav(whitelabel, {}, ORG_SCOPE, 'member'));
    expect(l).toContain('Discussions');
    expect(l).toContain('Work');
    expect(l).not.toContain('Settings');
    expect(l).not.toContain('Stewardship');
    expect(l).not.toContain('Records');
    expect(buildSettingsPane(ORG_SCOPE, 'member')).toEqual([]);
  });
});

// spec 348 / ADR-0046 / agent-vocabulary.md R.2–R.3 — the "You steward" pane lists what you steward, by KIND: two
// items for the two kinds a person stewards (Organizations = org-class, Services = service-class), then the surfaces
// that are about something other than a kind (Treasuries is about money, Household is a body you keep). What is
// YOURS rather than stewarded — Contacts, Grants, Search — sits in the person nav's own band; an alliance is an
// organization's relation and sits in the organization's pane. "Agents" as a list name is gone: every participant is
// an agent, including the person reading the list.
describe('the "You steward" pane', () => {
  const items = stewardshipPane({ kind: 'person' })[0]!.items.map((i) => i.id);

  it('names the two kinds a person stewards — never "agents" as a list', () => {
    expect(items).toEqual(expect.arrayContaining(['organizations', 'services']));
    expect(items).not.toContain('agents');
  });

  it('does not list app workspaces — you join those, you do not steward them; nor does the user menu (owner, 2026-10-01)', () => {
    expect(items).not.toContain('workspaces');
    const menu = buildUserMenu(whitelabel).map((i) => i.id);
    expect(menu).not.toContain('workspaces');
  });

  it('keeps the surfaces that are about something other than a kind; what is YOURS is in the person nav', () => {
    expect(items).toEqual(expect.arrayContaining(['treasuries', 'household']));
    expect(items).not.toContain('contacts'); expect(items).not.toContain('grants'); expect(items).not.toContain('search'); expect(items).not.toContain('alliances');
    const nav = labels(buildNav(whitelabel, {}, PERSON));
    expect(nav).toEqual(expect.arrayContaining(['Contacts', 'Grants', 'Search']));
    expect(nav).not.toContain('Agents');
  });

  it('an org workspace gets its own treasury surface and its alliances', () => {
    expect(stewardshipPane({ kind: 'org', org: '0x1' })[0]!.items.map((i) => i.id)).toEqual(['org-treasury', 'alliances']);
  });
});


describe('spec 422 — the Security pane', () => {
  it('Security in the user menu opens the third pane, and the pane takes no workspace scope', () => {
    const sec = buildUserMenu(whitelabel).find((i) => i.id === 'security');
    expect(sec?.opensPane).toBe('security');
    expect(sec?.href).toBe('/security');
    // paneGroups ignores scope for the security pane: it is about the signed-in person, whatever is open.
    expect(paneGroups('security', ORG_SCOPE, 'member')).toEqual(paneGroups('security', PERSON));
    expect(paneGroups('security')).toEqual(securityPane());
  });

  it('the pane answers its questions in order: overview · who can sign · what you let others do', () => {
    const headings = securityPane().map((g) => g.heading);
    expect(headings).toEqual(['Security', 'Who can sign', 'What you let others do']);
    const ids = securityPane().flatMap((g) => g.items.map((i) => i.id));
    expect(ids).toEqual(['sec-overview', 'sec-sign-in', 'sec-grants', 'sec-connected']);
  });

  it('Grants and Connected are CROSS-LINKS — one page, two doors — and every other row lives under /security', () => {
    for (const g of securityPane()) for (const i of g.items) {
      if (i.crossLink) expect(i.href.startsWith('/security')).toBe(false);
      else expect(i.href.startsWith('/security')).toBe(true);
    }
    expect(securityPane().flatMap((g) => g.items).filter((i) => i.crossLink).map((i) => i.href)).toEqual(['/grants', '/apps']);
  });

  it('no pane row is a placeholder: a page that has not shipped is absent, never a "soon" row', () => {
    for (const i of securityPane().flatMap((g) => g.items)) {
      expect(i.status).toBe('live');
      expect(i.disabledReason).toBeUndefined();
    }
  });
});


describe('spec 422 §8 — the Connected pane', () => {
  it('Connected in the user menu opens its pane; the pane takes no workspace scope', () => {
    const row = buildUserMenu(whitelabel).find((i) => i.id === 'apps');
    expect(row?.opensPane).toBe('connected');
    expect(row?.href).toBe('/apps');
    expect(paneGroups('connected', ORG_SCOPE, 'member')).toEqual(connectedPane());
  });
  it('one page per plain question, every row under /apps, none a placeholder', () => {
    const items = connectedPane().flatMap((g) => g.items);
    expect(items.map((i) => i.id)).toEqual(['con-overview', 'con-accounts', 'con-tools', 'con-signed-in', 'con-assistants', 'con-readers']);
    for (const i of items) { expect(i.href.startsWith('/apps')).toBe(true); expect(i.status).toBe('live'); expect(i.disabledReason).toBeUndefined(); }
    expect(connectedPane().map((g) => g.heading)).toEqual(['Connected', 'Your agent can use', 'Who may act as you']);
  });
});

describe('owner 2026-10-01 — the Developer tools pane', () => {
  it('"Your apps" became Developer tools and opens its pane; the pane takes no workspace scope', () => {
    const row = buildUserMenu(whitelabel).find((i) => i.id === 'developer');
    expect(row?.label).toBe('Developer tools');
    expect(row?.opensPane).toBe('developer');
    expect(row?.href).toBe('/developer');
    expect(buildUserMenu(whitelabel).map((i) => i.label)).not.toContain('Your apps');
    expect(paneGroups('developer', ORG_SCOPE, 'member')).toEqual(developerPane());
  });
  it('one page per thing: apps, the five evals surfaces, the kit — every resident row under /developer, none a placeholder', () => {
    const items = developerPane().flatMap((g) => g.items);
    expect(items.map((i) => i.id)).toEqual(['dev-overview', 'dev-apps', 'dev-evals-overview', 'dev-evals-skills', 'dev-evals-acts', 'dev-evals-techniques', 'dev-evals-gates', 'dev-evals-run', 'dev-registry']);
    for (const i of items) { expect(i.status).toBe('live'); expect(i.disabledReason).toBeUndefined(); if (!i.crossLink) expect(i.href.startsWith('/developer')).toBe(true); }
    expect(developerPane().map((g) => g.heading)).toEqual(['Developer tools', 'Evals', 'The kit']);
  });
});

describe('2026-10-09 — the Admin row', () => {
  it('is in the user menu only for an admin, and is never called Estate', () => {
    expect(buildUserMenu(whitelabel).map((i) => i.id)).not.toContain('admin');
    const row = buildUserMenu(whitelabel, { isAdmin: true }).find((i) => i.id === 'admin');
    expect(row?.label).toBe('Admin');
    expect(row?.href).toBe('/admin');
  });
});

describe('Admin in the sidebar (2026-10-21)', () => {
  const ids = (gs: NavGroup[]) => gs.flatMap((g) => g.items.map((i) => i.id));
  it('is last, below Settings, for an admin in their own workspace', () => {
    const gs = withAdminNav(buildNav(whitelabel), true, { kind: 'person' });
    expect(ids(gs).slice(-2)).toEqual(['settings', 'admin']);
  });
  it('is absent for everyone else, and inside an organization', () => {
    expect(ids(withAdminNav(buildNav(whitelabel), false, { kind: 'person' }))).not.toContain('admin');
    const org = { kind: 'org', org: '0x' + 'a'.repeat(40) } as const;
    expect(ids(withAdminNav(buildNav(whitelabel, {}, org as never), true, org as never))).not.toContain('admin');
  });
});
