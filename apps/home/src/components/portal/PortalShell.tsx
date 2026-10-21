'use client';
// The authenticated portal chrome: topbar (brand + workspace switcher + identity) + sidebar
// (desktop) / bottom-nav (mobile) + the routed section as <main>. The active WORKSPACE is
// derived from the URL (spec 315) and scopes the left nav: person / org / connected app.
import { HomeFooter } from '../shared/HomeFooter';
import { useState, type ReactNode, useEffect} from 'react';
import { ReadyProvider } from '../../ui/ready';
import { usePathname, useSearchParams } from 'next/navigation';
import { whitelabel } from '../../whitelabel/config';
import { useSession } from '../../context/session';
import { useManagedAgents } from './ManagedAgents';
import { parseWorkspacePath, orgHref } from '../../lib/workspace';
import { orgStatusOf, STATUS_LABEL } from '../../lib/org-lifecycle';
import { buildNav, buildSettingsPane, paneGroups, bottomNav, withAdminNav } from './nav';
import { useIsAdmin } from '../../home/use-is-admin';
import { useAskSelection, setAskSelection } from '../../home/ask-selection';
import type { AskCommand } from '../../home/ask-command';
import { useRegisteredName } from '../../lib/reverse-name';
import { PortalTopbar } from './PortalTopbar';
import { AskFlyout } from './ask/AskFlyout';
import { HuddleProvider } from './huddle/HuddleProvider';
import { HuddleDock } from './huddle/HuddleDock';
import { askIsAvailable } from '../../home/ask';
import { PortalSidebar } from './PortalSidebar';
import { PortalBottomNav } from './PortalBottomNav';
import { useInboxView } from '../../home/use-inbox';
import { nameLabel } from '../../lib/domain';

export function PortalShell({ children, appsBadge }: { children: ReactNode; appsBadge?: number }) {
  const [askOpen, setAskOpen] = useState(false);
  // The person's menu and the Ask share the right edge: opening one closes the other.
  const [menuOpen, setMenuOpen] = useState(false);
  const openAsk = (open: boolean) => { setAskOpen(open); if (open) setMenuOpen(false); };
  /** An ask a PAGE wants to start — "finish the payment you were waiting on". The shell owns whether the
   *  flyout is open, so a card deep in a page asks for it by event rather than by prop-drilling through
   *  every layer between them. Prefilled and not sent: the person still reads it and presses send. */
  const [askSeed, setAskSeed] = useState<string | null>(null);
  /** Spec 397 §6 — a PARKED run a page wants picked up (`/you?run=`): the flyout resumes it, and the person signs there. */
  const [askResume, setAskResume] = useState<string | null>(null);
  /** Spec 361 I4 — a COMMAND a screen handed the Ask (a supplied plan): the flyout runs it as the command picker would. */
  const [askCommandState, setAskCommand] = useState<AskCommand | null>(null);
  // Spec 361 I6 — what the current screen has selected, read here and handed to the Ask as context.
  const askSelection = useAskSelection();
  useEffect(() => {
    const onAsk = (e: Event) => {
      const detail = (e as CustomEvent<{ message?: string; resumeRun?: string; command?: AskCommand }>).detail;
      if (detail?.resumeRun) { setAskResume(detail.resumeRun); openAsk(true); return; }
      if (detail?.command) { setAskCommand(detail.command); openAsk(true); return; }
      const message = detail?.message;
      if (!message) return;
      setAskSeed(message);
      openAsk(true);
    };
    window.addEventListener('ap:ask', onAsk);
    return () => window.removeEventListener('ap:ask', onAsk);
  }, []);
  const pathname = usePathname();
  const searchParams = useSearchParams();
  // Spec 397 §6 — `/you?run=<runRef>`: the run an assistant parked for this person's signature. Read HERE, by the shell
  // that owns the flyout: a page's event fired on mount arrives before this shell's listener exists on a direct link.
  useEffect(() => {
    const run = pathname === '/you' ? (searchParams?.get('run') ?? '') : '';
    if (!/^(run|ask)-[A-Za-z0-9._:-]+$/.test(run)) return;
    setAskResume(run);
    openAsk(true);
  }, [pathname, searchParams]);
  // `?ask=<words>` on any workspace page: open the Ask on THIS workspace's agent with the words seeded, nothing sent — the
  // skills app's Runner hands an intent over this way (its own session is not a Home session, and the App-Delegation
  // scheme, spec 397 §4, is the in-app path still to be wired). The seed is read once; a value over 2000 chars is ignored.
  useEffect(() => {
    const seed = (searchParams?.get('ask') ?? '').trim();
    if (!seed || seed.length > 2000) return;
    setAskSeed(seed);
    openAsk(true);
  }, [pathname, searchParams]);
  // A selection belongs to the screen it was made on: leaving the screen clears it (spec 361 I6).
  useEffect(() => { setAskSelection(null); }, [pathname]);
  const active = parseWorkspacePath(pathname ?? '/');
  const { session, agentAddress, agentName, personName } = useSession();
  // 'any' (spec 342): the shell must name and route the workspace the URL points at, whatever the
  // org's lifecycle status — a deactivated org is hidden from lists, not made unreachable.
  const { agents } = useManagedAgents(session?.token ?? null, 'any');
  const isAdmin = useIsAdmin();
  const { view } = useInboxView(active.kind === 'person' ? session : null);
  const inboxUnread = active.kind === 'person' ? (view?.summary.unreadTotal ?? 0) : 0;
  const activeAgent = active.kind === 'org'
    ? agents.find((a) => a.agent.toLowerCase() === active.org.toLowerCase())
    : active.kind === 'service'
      ? agents.find((a) => a.agent.toLowerCase() === active.agent.toLowerCase())
      : undefined;
  const rel = active.kind === 'org' ? (activeAgent?.relationship ?? 'member') : 'steward';
  const workspaceName = activeAgent?.name ? nameLabel(activeAgent.name) : undefined;
  // An organization coordinates people by definition; a service agent does when it is a WORKSPACE. A
  // treasury or a registry has no roster, and a Members page that is always empty teaches nothing.
  const hasMembers = active.kind === 'org' || (active.kind === 'service' && activeAgent?.kind === 'workspace');
  const baseGroups = buildNav(whitelabel, {
    apps: appsBadge,
    inbox: inboxUnread > 0 ? inboxUnread : undefined,
  }, active, rel, workspaceName, hasMembers, activeAgent?.governor);
  // Admin, last in the sidebar, for the people on HOME_ADMINS only (the server answers; 2026-10-21).
  const groups = withAdminNav(baseGroups, isAdmin, active);
  // "Has a name" means the NAMING SERVICE resolves to this agent — not that the managed-agent row has a
  // label. A workspace's row says "Northern Colorado Field", which is a display label and not a name
  // anything can resolve; keying off it would call a nameless agent named.
  const activeSa = active.kind === 'org' ? active.org : active.kind === 'service' ? active.agent : agentAddress;
  const registered = useRegisteredName((activeSa ?? null) as `0x${string}` | null);
  const hasName = active.kind === 'person' ? !!agentName : (!registered.loaded || !!registered.name);
  const panes = {
    stewardship: paneGroups('stewardship', active, rel),
    settings: buildSettingsPane(active, rel, hasName),
    // spec 422 — the person's Security pane, the same from every workspace (it is about her, not the agent).
    security: paneGroups('security'),
    connected: paneGroups('connected'),
    developer: paneGroups('developer'),
  };
  const tabs = bottomNav(baseGroups);
  // spec 342 — the workspace of a deactivated or deleted org still opens (a hidden row is a view
  // decision, not a locked door), but it must SAY why it is missing from everywhere else.
  const orgStatus = active.kind === 'org' && activeAgent ? orgStatusOf(activeAgent) : 'active';
  // THE ASK (spec 350 §3.5) — addressed to the realm you are standing in, which is the same scope the
  // sidebar uses. The person's own realm is their SA; an org's or a service's is the one in the URL.
  const askAddressee = (active.kind === 'person' ? agentAddress : activeSa) as `0x${string}` | null;
  const askLabel = active.kind === 'person'
    ? (agentName ? nameLabel(agentName) : 'your agent')
    : (workspaceName ?? (activeAgent?.name ? nameLabel(activeAgent.name) : undefined) ?? 'this workspace');
  // The Ask needs the harness, and the harness needs the enforcer that binds a mandate to ONE request.
  // Where that is not deployed (Base Sepolia today), there is no Ask — not a button that fails when
  // pressed. One signal, read from the deployment this build targets.
  const canAsk = !!session && !!askAddressee && askIsAvailable();
  // Spec 378 — the dock lives here, above everything, so a call survives navigation; a huddle is STARTED
  // where a team already talks (its discussion topics, `OrgDiscussionsView`), each topic its own room.
  const nameOfAgent = (a: string): string | undefined => {
    const hit = agents.find((x) => x.agent.toLowerCase() === a.toLowerCase());
    if (hit?.name) return nameLabel(hit.name);
    if (agentAddress && a.toLowerCase() === agentAddress.toLowerCase()) return agentName ? nameLabel(agentName) : 'you';
    return undefined;
  };
  return (
    <HuddleProvider>
    <div className="portal-root">
      <PortalTopbar brandName={whitelabel.brand.name} {...(canAsk ? { askOpen, onToggleAsk: () => openAsk(!askOpen) } : {})} menuOpen={menuOpen} onMenuOpenChange={(open) => { setMenuOpen(open); if (open) setAskOpen(false); }} />
      <HuddleDock nameOf={nameOfAgent} />
      <div className="portal-body">
        <PortalSidebar groups={groups} panes={panes} workspaceName={workspaceName} personName={personName ?? (agentName ? nameLabel(agentName) : null)} />
        <main className="portal-main">
          {orgStatus !== 'active' && active.kind === 'org' && (
            <div
              role="status"
              style={{
                margin: '0 0 1rem', padding: '.6rem .8rem', borderRadius: 10, fontSize: '.85rem',
                background: 'var(--color-amber-50, #fffbeb)', color: 'var(--color-amber-800, #92400e)',
                border: '1px solid var(--color-amber-200, #fde68a)',
              }}
            >
              This organization is <b>{STATUS_LABEL[orgStatus].toLowerCase()}</b> — hidden from the rest of your
              home. Its records, address and delegations are untouched. Change that under{' '}
              <a href={orgHref(active.org, 'status')}>Settings → Status</a>.
            </div>
          )}
          <ReadyProvider key={pathname}>{children}</ReadyProvider>
          <HomeFooter />
        </main>
      </div>
      <PortalBottomNav groups={groups} tabs={tabs} panes={panes} workspaceName={workspaceName} />
      {askOpen && canAsk && (
        <AskFlyout
          seed={askSeed}
          onSeedUsed={() => setAskSeed(null)}
          resumeRun={askResume}
          onResumeUsed={() => setAskResume(null)}
          command={askCommandState}
          onCommandUsed={() => setAskCommand(null)}
          addressee={askAddressee!} addresseeLabel={askLabel}
          // The app knows where you are standing and what you are to this agent; the Ask should not have
          // to infer it from a sentence.
          // The Ask asks what CLASS of agent you are addressing, and a persona is person-class: you are it.
          realm={{ kind: active.kind === 'persona' ? 'person' : active.kind }}
          selection={askSelection}
          onClose={() => setAskOpen(false)}
        />
      )}
    </div>
    </HuddleProvider>
  );
}
