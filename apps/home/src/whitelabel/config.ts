// The active white-label config for this deployment: the FAITH vertical ("Impact"). This is
// the only place faith/vertical copy + the relying-app registry live for the central trust
// site (ADR-0021 — app level, never packages). The member-facing lexicon is documented in
// docs/portal-lexicon.md; this config is its single source of truth. Swapping verticals is a
// new config, not a code change.
import { A2A_DOMAIN, AGENT_NAME_PARENT, CONNECT_DOMAIN, HOME_MCP_ORIGIN, VAULT_SERVER_ID } from '../lib/domain';
import type { WhiteLabelConfig } from './schema';

/**
 * The relying origins a deployment adds to a client's registry, newest shape first.
 *
 * Home refuses to show a sign-in screen for a `redirect_uri` whose origin is not registered for
 * that client — the user sees "Request blocked". Gather27 is THREE websites since round-4 D14 (the
 * host surface, the public map, the operator console) and the registry took exactly one origin, so
 * signing in from ops or find was blocked while the host surface worked.
 *
 * `plural` is a comma-separated list; `singular` is the older one-value variable, kept as a
 * fallback so a deployment that has not been updated behaves exactly as it did. Neither set means
 * an EMPTY list, which is what keeps production's registry unchanged.
 */
export function extraOrigins(plural: string | undefined, singular: string | undefined): string[] {
  const raw = plural ?? singular ?? '';
  // Trim and drop empties: a trailing comma in a dashboard field must not register a blank origin.
  return raw.split(',').map((s) => s.trim()).filter(Boolean);
}

/** Gather27's non-host surfaces are hostname LABELS on the same site — see `surfaceFor` in
 *  gather27-web/src/surface.ts, which reads exactly these. */
const GATHER_SURFACE_LABELS = ['ops', 'find'] as const;

/**
 * Every Gather27 surface origin a deployment implies, host surface first.
 *
 * D14 split Gather into three websites that are three labels on ONE site: the bare hostname is the
 * host surface, `ops.` the operator console, `find.` the public map. A deployment names its Gather
 * site once, and all three follow from it — naming one and being blocked on the other two is the
 * bug this closes, and it is not worth a second dashboard field that can drift out of step with the
 * first.
 *
 * Deriving siblings does not widen trust to anyone new: they are labels inside a DNS zone whoever
 * set the configured origin already controls. A deployment that names no Gather origin still gets
 * an empty list, which is what keeps the production broker's registry unchanged.
 *
 * Whichever surface is configured, the same three come out — the bare host is recovered first, so
 * setting the ops URL by mistake still registers all three in the right order.
 */
// The ways in are an estate decision, not a code one. A Home whose members all sign in by email hides
// Google without a deploy; a Home that opens YouVersion says so here. The value is the display order.
// An entry that is not a method is DROPPED with a warning rather than opening a door by typo, and if
// nothing valid remains the default stands — a misspelt variable must never produce a Home with no
// way in. This governs what a NEW person is offered; the returning-member lane ignores it on purpose
// (lib/named-home-door.ts), so hiding a method here never locks out a home made with it.
export type CredentialMethod = 'passkey' | 'wallet' | 'google' | 'youversion' | 'email' | 'phone';
const CREDENTIAL_METHODS: readonly CredentialMethod[] = ['passkey', 'wallet', 'google', 'youversion', 'email', 'phone'];
export function credentialMethodsFromEnv(raw: string | undefined, fallback: readonly CredentialMethod[]): CredentialMethod[] {
  const picked = (raw ?? '').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
  if (picked.length === 0) return [...fallback];
  const valid: CredentialMethod[] = [];
  for (const p of picked) {
    if ((CREDENTIAL_METHODS as readonly string[]).includes(p)) { if (!valid.includes(p as CredentialMethod)) valid.push(p as CredentialMethod); }
    else console.warn(`NEXT_PUBLIC_CREDENTIAL_METHODS: "${p}" is not a method (one of ${CREDENTIAL_METHODS.join(', ')}); ignored`);
  }
  return valid.length > 0 ? valid : [...fallback];
}

export function gatherSurfaceOrigins(plural: string | undefined, singular: string | undefined): string[] {
  const out: string[] = [];
  const add = (u: string) => { if (!out.includes(u)) out.push(u); };
  for (const entry of extraOrigins(plural, singular)) {
    let url: URL;
    try { url = new URL(entry); } catch { add(entry); continue; }
    const host = url.hostname.toLowerCase();
    // localhost and IPs address the three surfaces by PATH, not by subdomain, and have no sibling
    // hostnames to derive. workers.dev is a flat namespace — `ops.<name>.workers.dev` is not a
    // thing. Register what was given and derive nothing.
    if (host === 'localhost' || /^[0-9.]+$/.test(host) || host.endsWith('.workers.dev')) { add(url.origin + '/'); continue; }
    const bare = GATHER_SURFACE_LABELS.reduce((h, l) => (h.startsWith(l + '.') ? h.slice(l.length + 1) : h), host);
    // HOST surface first: several consumers take the first https URI as the app's canonical address.
    for (const h of [bare, ...GATHER_SURFACE_LABELS.map((l) => l + '.' + bare)]) {
      const d = new URL(url.toString());
      d.hostname = h;
      add(d.origin + '/');
    }
  }
  return out;
}

/** The footer links, from `NEXT_PUBLIC_FOOTER_LINKS` (a JSON array of `{label, href}`) or the defaults. A value
 *  that does not parse to such an array is refused loudly at build, never silently swapped for the defaults. */
export function footerLinks(raw: string | undefined, defaults: ReadonlyArray<{ label: string; href: string }>): ReadonlyArray<{ label: string; href: string }> {
  const v = (raw ?? '').trim();
  if (!v) return defaults;
  let parsed: unknown;
  try { parsed = JSON.parse(v); } catch { throw new Error('NEXT_PUBLIC_FOOTER_LINKS is not JSON'); }
  if (!Array.isArray(parsed) || !parsed.every((l) => l && typeof l === 'object' && typeof (l as { label?: unknown }).label === 'string' && typeof (l as { href?: unknown }).href === 'string' && /^https:\/\//.test((l as { href: string }).href))) {
    throw new Error('NEXT_PUBLIC_FOOTER_LINKS must be a JSON array of { label, href } with https hrefs');
  }
  return parsed as ReadonlyArray<{ label: string; href: string }>;
}

const faithImpact: WhiteLabelConfig = {
  id: 'faith-impact',
  brand: {
    // Deployment-configurable (NEXT_PUBLIC_BRAND_*) so the SAME code brands per host — "Impact" on
    // impact-agent.me, "Faithnet" on faithnet.me — without a code change. Defaults preserve Impact.
    name: process.env.NEXT_PUBLIC_BRAND_NAME || 'Impact',
    community: process.env.NEXT_PUBLIC_BRAND_COMMUNITY || 'missional community',
    tagline: process.env.NEXT_PUBLIC_BRAND_TAGLINE || 'Your home in the missional community',
  },
  // Domains stay sourced from lib/domain.ts (the ADR-0021 single source of hostnames).
  domains: { connect: CONNECT_DOMAIN, a2a: A2A_DOMAIN, nameParent: AGENT_NAME_PARENT },
  // The footer cross-links (the substrate, the skills library, the studio that designs the ontologies).
  // Outbound only, and only to sites of ours: the SEO these carry runs both ways, and a Home never links
  // out to a stranger. `NEXT_PUBLIC_FOOTER_LINKS='[{"label":"…","href":"https://…"}]'` replaces the set.
  footer: {
    credit: process.env.NEXT_PUBLIC_FOOTER_CREDIT || 'Built on Agentic Primitives — authority for agents that the agent cannot exceed.',
    links: footerLinks(process.env.NEXT_PUBLIC_FOOTER_LINKS, [
      { label: 'Agentic Primitives', href: 'https://agenticprimitives.dev' },
      { label: 'Ontology & namespaces', href: 'https://agenticprimitives.dev/ontology' },
      { label: 'Developers', href: 'https://agenticprimitives.dev/developers' },
      { label: 'Skills library', href: 'https://skills.faithnet.io' },
      { label: 'Rich Canvas — ontology studio', href: 'https://richcanvas3.com' },
    ]),
  },
  onboarding: {
    // The ways in, in the order the front door offers them. Default (2026-09-13): Google · email; wallet,
    // passkey, phone and YouVersion are OFF — a passkey cannot sign on faithchain, and the door stays two
    // doors, both nameless. An estate overrides the set with NEXT_PUBLIC_CREDENTIAL_METHODS (see
    // credentialMethodsFromEnv above): the default is Faithnet's door, and no estate has to fork to change it.
    credentialMethods: credentialMethodsFromEnv(process.env.NEXT_PUBLIC_CREDENTIAL_METHODS, ['google', 'email']),
  },
  services: { devices: true, connectedApps: true },
  // The stewardship hub: what the member helps oversee / manage / protect from their home.
  manageableAgents: [
    { id: 'person', label: 'You', blurb: 'Your personal home — the you the community knows.', status: 'live' },
    { id: 'organization', label: 'Organizations', blurb: 'Ministries, churches, and teams you help oversee.', status: 'live', verb: 'oversee' },
    { id: 'treasury', label: 'Treasuries', blurb: 'Funds and giving you help manage.', status: 'live', verb: 'manage' },
    { id: 'data-source', label: 'Data sources', blurb: 'Records you help protect and share, with consent.', status: 'soon', verb: 'protect' },
  ],
  relyingApps: [
    // skills-app — the SKILL.md management app (agentictrustlabs/skills). Login-grade connect via the
    // Personal Home; no PII held by the broker. aud = client_id; the allowed origin is derived from
    // the exact-match redirect_uri (CN-1) by `src/lib/oidc-clients.ts`.
    //
    // `org-create` because a DOMAIN in that app is an ORGANIZATION in the member's own Home: it holds
    // the domain's skill folders (its library), its knowledge base (its vault) and the agent that runs
    // them. One org per domain, deployed by the member's own credential in a single consent — the app
    // cannot mint it, which is the point. Requests arrive name-deferred (empty `agent_name`) with
    // `org_base=<domain label>`, so they route through RecognizedEnroll's org-create leg.
    // Spec 397 — THE HOME MCP: Claude.ai's entrance to a person's own agent. A registered relying app like any
    // other (it never runs a credential ceremony of its own); the ONE template it may request is `ask-as-me`,
    // a delegation from the person to the Home MCP's key pinned to `harness.ask` — the right to put a question
    // to their agent as them, revocable on chain, and nothing more. `delegate` is that key (the Worker's
    // secret's address), the same shape as an agent's session wire.
    // Which Worker and which key are THIS deployment's: `HOME_MCP_ORIGIN` (src/lib/domain.ts — its origin, the same
    // one the front door prints as the connector URL) and `NEXT_PUBLIC_HOME_MCP_DELEGATE` (its key's address); unset
    // ⇒ faithnet's, the estate Ring 0 deploys.
    {
      client_id: 'home-mcp',
      name: 'Assistant via Home MCP',
      redirect_uris: [
        `${HOME_MCP_ORIGIN}/oauth/callback`,
        // The Worker's workers.dev host — the connector URL until 2026-09-21; a connection made under it still completes there.
        'https://home-mcp-faithnet.richardpedersen3.workers.dev/oauth/callback',
        'http://localhost:8797/oauth/callback',
      ],
      allowed_scopes: ['openid', 'agent'],
      allowed_delegation_templates: ['ask-as-me'],
      delegate: (process.env.NEXT_PUBLIC_HOME_MCP_DELEGATE || '0x2D16473370b654D75FCf9cC37649BBd86B9Aff70') as `0x${string}`,
    },
    // Spec 397 §11 — THE SAME WORKER AS AN ACT CLIENT. A second registration, not a second scope on the first: the
    // `home-mcp` client's allowed templates stay ask-as-me only, so nothing a dynamic registration (Claude's) can
    // request reaches this one. `delegate` is the Worker's ACT key (a second secret, never the ask key): every
    // standing wire of the set names it. `ask_delegate` is still the ask key — the ask-as-me wire that admits the
    // ask rides the same ceremony. A stolen ask key still cannot pay.
    {
      client_id: 'home-mcp-act',
      name: 'Assistant via Home MCP (acts you pre-authorized)',
      redirect_uris: [
        `${HOME_MCP_ORIGIN}/oauth/callback`,
        'https://home-mcp-faithnet.richardpedersen3.workers.dev/oauth/callback',
        'http://localhost:8797/oauth/callback',
      ],
      allowed_scopes: ['openid', 'agent'],
      allowed_delegation_templates: ['act-as-me'],
      delegate: (process.env.NEXT_PUBLIC_HOME_MCP_ACT_DELEGATE || '0x0eE38D01753149EE75f68f42FcBCA5eDb94B3434') as `0x${string}`,
      ask_delegate: (process.env.NEXT_PUBLIC_HOME_MCP_DELEGATE || '0x2D16473370b654D75FCf9cC37649BBd86B9Aff70') as `0x${string}`,
    },
    {
      client_id: 'skills-app',
      name: 'Skills',
      // EXACT MATCH (CN-1) — a redirect_uri that is not listed here is refused, so the app's own
      // custom domain has to be registered before anyone can sign in from it. FIRST on purpose: the
      // front-channel sign-out (app/logout) takes the first https URI per client for the `/sso-logout`
      // hop, and on faithnet that must reach skills.faithnet.io. The pages.dev origin stays — it is
      // the Pages project's permanent hostname and what preview deploys serve from.
      redirect_uris: [
        'https://skills.faithnet.io/',
        'https://skills-web-7ar.pages.dev/',
        'http://localhost:5190/',
      ],
      allowed_scopes: ['openid', 'agent'],
      allowed_delegation_templates: ['site-login', 'org-create', 'service-agent-wire'],
      delegate: '0x89D13c596c45E4eE80Af5ae06C727FE9A820ffD0',
      // `skills-agent.impact` — the service agent orgs grant to and skills-a2a signs AS. It is
      // custodied by a SIWE credential in its owner's Home, NOT by skills-a2a: the worker signs with
      // a KMS key that the `service-agent-wire` ceremony authorizes as a DELEGATE, so a compromise of
      // the worker yields something the custodian revokes rather than the identity itself
      // (ADR-0019 + docs/architecture/agent-rules/service-agent-signing.md).
      //
      // It replaces 0x2aF8853D…, which was deployed custodied by the KMS key DIRECTLY — "no held
      // key" but the service was still the custodian, which is the shape the rule forbids. Grants
      // minted to that address name a delegate this worker can no longer present a wire for and must
      // be re-minted. NOT the shared `delegate` above, which a dozen entries name.
      //
      // A DIFFERENT SA PER IDENTITY UNIVERSE, same as field-app below: the faithnet deploy sets
      // NEXT_PUBLIC_SKILLS_SERVICE_SA to `skills-service.svc` on 34348
      // (0x6F976a629b170b705E21c39D3489892FBbe9a86b) — minted and custodied SOLELY by its owner's
      // SIWE account, which is why it replaced the demo-persona-custodied `skills-agent.svc`
      // (0x6723CBCE…aAe0) this repo had seeded. The default stays base-sepolia's. Without the
      // override, a faithnet org's grant names an identity that has no code on faithchain and
      // skills-a2a can present no wire for it — a refusal at the far side with no local symptom.
      operational_delegate:
        process.env.NEXT_PUBLIC_SKILLS_SERVICE_SA || '0x9c9b7aDd48B001CC3b4672911972b2e6feDCC95F',
      // Where the service-agent-wire ceremony talks to skills-a2a. One worker name, both universes:
      // the skills stack CUT OVER to faithnet in place rather than running a parallel deployment,
      // so `skills-a2a-production` IS the faithnet worker. Overridable all the same.
      serviceAgentConfig: {
        a2aBase:
          process.env.NEXT_PUBLIC_SKILLS_A2A_BASE ||
          'https://skills-a2a-production.richardpedersen3.workers.dev',
      },
    },
    // commons-app — the reference third-party app from the PUBLIC starter repo
    // (agentic-primitives-starter, apps/commons). It is the one entry here that exists to be COPIED:
    // a plain relying app with no privileged template, no social custody, and no payment config —
    // exactly what a member gets from the self-service registry at /developer.
    //
    // It is curated rather than self-registered only so the starter runs against a fresh deployment
    // before anyone has opened the portal. A developer deploying their own copy registers THEIR
    // origin at /developer instead of editing this file.
    {
      client_id: 'commons-app',
      name: 'Commons',
      // The deployed starter, plus `wrangler dev` on 8799. Exact match (CN-1), so the trailing
      // slash is load-bearing — and note the `-production` suffix: `wrangler deploy --env
      // production` names the Worker `<name>-<env>`, so the origin is NOT `commons.workers.dev`.
      // A developer deploying their own copy adds THEIR origin through /developer, not here.
      redirect_uris: [
        'https://commons-production.richardpedersen3.workers.dev/',
        'http://localhost:8799/',
        'http://127.0.0.1:8799/',
      ],
      allowed_scopes: ['openid', 'agent'],
      allowed_delegation_templates: ['site-login', 'org-create'],
      delegate: '0x89D13c596c45E4eE80Af5ae06C727FE9A820ffD0',
    },
    // engage-app — the engagement layer for faith and impact work (agentictrustlabs/engage). Turns a
    // stated need into a mandate-authorized, receipted fulfilment. Login-grade connect via the
    // Personal Home; no PII held by the broker.
    //
    // `org-create` for the same reason skills has it: a DOMAIN in that app is an ORGANIZATION in the
    // member's own Home, holding the domain's published needs/offerings and the agent that runs
    // them. One org per domain, deployed by the member's own credential in a single consent — the
    // app cannot mint it, which is the point.
    {
      client_id: 'engage-app',
      name: 'Engage',
      // A redirect_uri is exact-match (CN-1) and is where this broker HANDS OVER an authorization
      // code, so it must name a domain we CONTROL — never a guessed one. An earlier revision of this
      // entry read `https://engage.pages.dev/`, inferred from the project name; that domain belongs
      // to someone else. Cloudflare appends a suffix when a project name is taken, and it did here:
      // the project is `engage-web`, the domain is `engage-web-7um.pages.dev`. Read from
      // `wrangler pages project list`, never derived.
      redirect_uris: [
        'https://engage-web-7um.pages.dev/',
        'http://localhost:5173/',
        // Local-stack dev: engage-web moves off 5173 (demo-web holds it there) to 5177.
        'http://localhost:5177/',
        // Field Workspace still sends `engage-app` today (field-a2a accepts that audience until
        // field-app tokens exist). Without this exact URI, Home fail-closes the enroll as
        // "Request blocked / Only start setup from a site you trust." Comes off this list once
        // field-web's CLIENT_ID is `field-app`.
        'https://field-web.richardpedersen3.workers.dev/',
        'http://localhost:5174/',
        'http://127.0.0.1:5174/',
      ],
      allowed_scopes: ['openid', 'agent'],
      allowed_delegation_templates: ['site-login', 'org-create', 'service-agent-wire'],
      delegate: '0x89D13c596c45E4eE80Af5ae06C727FE9A820ffD0',
      // `engage-service.impact` — the service agent orgs grant to and engage-a2a signs AS. Custodied
      // OUTSIDE engage-a2a (1 custodian, 0 passkeys on chain today); the worker signs with a KMS key
      // the `service-agent-wire` ceremony authorizes as a DELEGATE, so compromising the worker
      // yields something the custodian revokes rather than the identity itself (ADR-0019 +
      // docs/architecture/agent-rules/service-agent-signing.md).
      //
      // engage-a2a asserts that separation at RUNTIME rather than trusting this comment: it reads
      // `isCustodian(kmsKey)` on this SA before its first signature and refuses to start if the key
      // it signs with is also a custodian of the identity it signs as. See engage's
      // `apps/engage-a2a/src/custody.ts`.
      //
      // NOT the shared `delegate` above, which a dozen entries name — operational authority granted
      // to that address is granted to all of them.
      operational_delegate: '0x0d9be26B9F52AF06354c3eFA19173BcBA60176d3',
      // Where the service-agent-wire ceremony talks to engage-a2a.
      serviceAgentConfig: { a2aBase: 'https://engage-a2a-production.richardpedersen3.workers.dev' },
    },
    // field-app — Field Circles / Field Workspace (agentictrustlabs/engage apps/field-*).
    // A SEPARATE product (ADR-0007), not a mode of Engage. Login-grade connect via the Personal
    // Home; no PII held by the broker. No service-agent-wire yet — field-a2a signs nothing as
    // itself until F2 (outbound send). operational_delegate is field-service.impact, not the
    // shared `delegate` below.
    {
      client_id: 'field-app',
      name: 'Field',
      redirect_uris: [
        // faithnet universe (chain 34348) — only present when the deploy sets it (field.faithnet.io);
        // production's list is unchanged. Same env-gating as gather-app below. FIRST on purpose:
        // the front-channel sign-out (app/logout) takes the first https URI per client for the
        // `/sso-logout` hop, and a faithnet sign-out must reach field.faithnet.io, not production.
        ...(process.env.NEXT_PUBLIC_FIELD_ORIGIN ? [process.env.NEXT_PUBLIC_FIELD_ORIGIN] : []),
        'https://field-web.richardpedersen3.workers.dev/',
        'http://localhost:5174/',
        'http://127.0.0.1:5174/',
        // HeartCoach (agentictrustlabs/engage apps/coach-*) signs in AS field-app until `coach-app` is
        // registered here — a RECORDED WIDENING (owner decision 2026-09-28, option B): a Field token also
        // serves HeartCoach. Fixed, known URLs, present on every deploy (same reasoning as
        // churchglobalgather27 under gather-app). Comes off this list, and coach-a2a's SESSION_AUDS
        // drops field-app, the day coach-app is a client of its own.
        'https://coach.faithnet.io/',
        'https://heartcoach.faithnet.io/',
        'http://localhost:5176/',
        'http://127.0.0.1:5176/',
      ],
      allowed_scopes: ['openid', 'agent'],
      allowed_delegation_templates: [
        'site-login',
        'org-create',
        'workspace-create',
        // P4 — workspace membership, two ceremonies around one stash (/connect/workspace-invite):
        // the custodian signs the member's access in; the member claims it into their own tree.
        'workspace-member-invite',
        'workspace-join',
        'service-agent-wire',
        // Spec 397 — the person's wire to field-a2a's OWN key, pinned to harness.ask: Field's Ask, off the
        // workspace's screens (DMs, Activity, Files), puts the question to the person's own agent as them.
        'ask-as-me',
      ],
      delegate: '0x89D13c596c45E4eE80Af5ae06C727FE9A820ffD0',
      // The key field-a2a signs A2A-Session assertions with — its AKCS custody key, a DIFFERENT one per
      // universe (faithnet sets NEXT_PUBLIC_FIELD_ASK_DELEGATE to the 34348 key; the default is
      // production's). It must equal field-a2a's KMS_SIGNER_ADDRESS or the wire names a key the
      // Worker cannot present.
      ask_delegate: (process.env.NEXT_PUBLIC_FIELD_ASK_DELEGATE || '0xb6fb1ce89c3d3d8da7df378ed5cdc6e79cdc9260') as `0x${string}`,
      libraryFolders: ['field'],
      // Spec 412 W6 — Field reads the person's OWN messages (the DMs screen; the game's whispers land
      // in a character's inbox). demo-signin mints this on every sign-in (enter-as included), person →
      // the interactions service SA, revocable by the person alone at Home. `inbox.get` needs
      // `vault:inbox.data`; `inbox.body.get` needs `vault:message.body:dm:*` (interactions-do OP_RESOURCE).
      read_grant: { resources: ['vault:inbox.data', 'vault:message.body:dm:*'] },
      // field-service.impact — a DIFFERENT SA per identity universe (the faithnet deploy sets
      // NEXT_PUBLIC_FIELD_SERVICE_SA to the SA minted on 34348; default is base-sepolia's).
      operational_delegate:
        process.env.NEXT_PUBLIC_FIELD_SERVICE_SA || '0xD1F7Ef18537eFDBfE0cA265F60f7A59333066f20',
      serviceAgentConfig: {
        a2aBase:
          process.env.NEXT_PUBLIC_FIELD_A2A_BASE ||
          'https://field-a2a-production.richardpedersen3.workers.dev',
      },
    },
    // gather-app — Gather27 (agentictrustlabs/engage apps/gather27-*). Find a group near you;
    // invite-driven host onboarding; events live in the host org vault. Login-grade connect via
    // the Personal Home.
    //
    // `service-agent-wire` — the Gather27 WORKSPACE is a service-class agent (kind 'workspace',
    // ADR-0046: a service ROLE that mirrors treasury, never extends it). Its vault holds the roster
    // of member organizations; the ceremony authorizes gather27-a2a's KMS key as the workspace's
    // DELEGATE, and that wire is the ONLY delegation the roster read path presents. The workspace is
    // custodied by the Gather org's custodian, who runs the ceremony from Home against a2aBase.
    {
      client_id: 'gather-app',
      // Gather's own brand is ONE word, "Gather27" (Clayton, 2026-10-07), and the enroll screen shows
      // this verbatim as "Continue to <name>".
      name: 'Gather27',
      description: 'Find and list Gather groups.',
      // Round-4 — Gather is starting hosts on ONE door. A host arrives from a Gather registration
      // email, so email is the method they already proved they have; offering four more is four
      // more ways for a church admin to get stuck. Everything else still works and is one line
      // away — see `signInMethods` in whitelabel/schema.ts.
      signInMethods: ['email'],
      // faithnet demo (chain 34348): let a phone/Google sign-in bootstrap a KMS-custodied home
      // THROUGH the gather connect flow. Off by default so production impact-agent.me keeps the
      // login-grade posture (a relying app does not mint custody). ADR-0011 still holds: the phone
      // is contact-control, and C_sub (KMS), not the phone, is the on-chain custodian.
      socialCustody: process.env.NEXT_PUBLIC_GATHER_SOCIAL_CUSTODY === 'true',
      redirect_uris: [
        // faithnet universe (chain 34348) — only present when the deploy sets it; production's list
        // is unchanged. Round-4 D14 made Gather THREE websites, so this is a LIST: set
        // NEXT_PUBLIC_GATHER_ORIGINS to the host surface, the ops console and the public map.
        // Without all three, signing in from the missing one shows "Request blocked".
        //
        // FIRST on purpose, and the HOST surface first within the list: several consumers take the
        // first https URI as the app's canonical address — the org-invite return URL
        // (server/connect/org-invite-lookup.ts) and the front-channel sign-out hop. Those must reach
        // the faithnet host surface, not the workers.dev deployment below and not the ops console.
        // Same reasoning as field-app above.
        ...gatherSurfaceOrigins(process.env.NEXT_PUBLIC_GATHER_ORIGINS, process.env.NEXT_PUBLIC_GATHER_ORIGIN),
        'https://gather27-web.richardpedersen3.workers.dev/',
        'http://localhost:5175/',
        'http://127.0.0.1:5175/',
        // churchglobalgather27 — sibling fork of gather27-web/gather27-a2a sharing this same Home
        // (faithnet.me) for its connect flow. Fixed, known URL; present on every deploy, same as the
        // two production defaults above.
        'https://gather27-web-churchglobal.richardpedersen3.workers.dev/',
      ],
      allowed_scopes: ['openid', 'agent'],
      allowed_delegation_templates: ['site-login', 'org-create', 'service-agent-wire'],
      delegate: '0x89D13c596c45E4eE80Af5ae06C727FE9A820ffD0',
      // Where the service-agent-wire ceremony talks to gather27-a2a.
      serviceAgentConfig: { a2aBase: process.env.NEXT_PUBLIC_GATHER_A2A_BASE || 'https://gather27-a2a-production.richardpedersen3.workers.dev' },
      // Each host org grants the WORKSPACE a read of its own listing record at connect time: the
      // workspace roster reads listings in place, never copies them (org_read_grant — see schema).
      org_read_grant: {
        delegate: (process.env.NEXT_PUBLIC_GATHER_WORKSPACE_SA || '0xcE7bb378e132Cd373B366746B5F43533f9777Da7') as `0x${string}`, // gather27-workspace (faithnet SA when set)
        server: VAULT_SERVER_ID,
        resources: ['vault:gather27:listing'],
      },
      // spec 345 — round-2 D3 individual custody: a person publishing under their own name (no
      // org) needs read+write on their OWN vault's listing record, minted on plain sign-in. Fixes
      // the self-as-org incident (existingOrg pointed at the person's own address wrote a bogus
      // kind:'org' impact-relationships entry) by never touching org machinery at all.
      self_vault_grant: {
        server: VAULT_SERVER_ID,
        resources: ['vault:gather27:listing'],
        ops: ['read', 'write'],
      },
      // Sign-in performance, measured live 2026-09-15: pressing Allow to the popup closing took 31 s,
      // of which ~18 s was the community-messaging wire provisioned once per managed org and ~11 s
      // the related-orgs read that only feeds it. Gather registers no messaging capability, so it
      // gets neither. Gated HERE, per client: every other app is untouched (whitelabel/provisioning.test.ts).
      provisioning: { communityMessaging: false },
      // ...and 4.4 s was an on-chain approval of two digests that never change between sign-ins
      // (site grant + self-vault grant). Reuse the standing grant instead; a refused reuse still
      // falls back to a fresh mint (RecognizedEnroll).
      standingGrant: 'with-self-vault',
      // Gather asks a host for an email twice today: once to sign in, once on the listing form. The
      // second one was a different address nobody reconciled, so it is being removed and the signed-in
      // address takes its place (R5.3, 2026-09-15). The value is the member's OWN verified email off
      // their vault profile, handed over at /oidc/authorize-grant and re-gated there against this list;
      // consent says so on the sheet. Only this client: whitelabel/provisioning.test.ts pins that.
      idTokenClaims: ['email'],
      // Gather's OWN consent wording (Clayton, 2026-10-07). A Gather host is a church admin listing a
      // group: the shared lines — funds, custody, recovery, sign-in methods, "the missional community" —
      // describe things Gather never touches and read as alarms. The shared templates are every app's,
      // so Gather says it in its own words HERE (whitelabel/client-consent.ts); nothing else moves.
      // "See your name and email" is the disclosure for `idTokenClaims` above — the override replaces
      // the helper's email line, so it must say it itself (client-consent.test.ts pins that).
      // service-agent-wire is run by Gather's own operators, not hosts, and keeps the shared text.
      consent: {
        templates: {
          'site-login': {
            canDo: ['Sign you in to Gather27', 'See your name and email', 'Set up your church’s listing'],
            hideCannotDo: true,
          },
          'org-create': {
            canDo: ['Sign you in to Gather27', 'See your name and email', 'Set up your church’s listing'],
            hideCannotDo: true,
          },
        },
        signedInAs: 'email',
        // Same switch-account action as everyone's; a host signed in with an EMAIL, not a custodian.
        switchAccountLabel: 'Not you? Use a different email',
        // A host's "organization" is their church's listing; and the account they manage it from is
        // their Global.Church ID, not an "Impact home".
        orgCreate: {
          explainer: 'This single approval sets up {org}. Your church gets its own listing page on {app}. Nothing beyond that.',
          disconnect: 'You can disconnect {app} any time from your Great Commission ID.',
          receipt: 'Your church is set up.',
        },
        hideSubstrate: true,
        copy: { portalStepBusy: 'Signing you in…' },
        // The shared ceremony narration says "chain", "custody" and "keys"; a host should read none of it.
        progressText: {
          'Confirming it on the chain…': 'Confirming…',
          'This is how Gather27 gets a scoped, revocable grant — never custody.': 'This can take a moment.',
          'One approval — Gather27 never holds its keys.': 'This can take a moment.',
          'The listing will live here — Gather27 only gets a read grant.': 'Your listing will live here.',
        },
      },
    },
    // skills-corpus — the SKILL.md ceremony/admin surface (owner claims a skillset).
    {
      client_id: 'skills-corpus',
      name: 'Skills Corpus (admin)',
      redirect_uris: ['https://skills-corpus.richardpedersen3.workers.dev/', 'http://localhost:8996/'],
      allowed_scopes: ['openid', 'agent'],
      allowed_delegation_templates: ['site-login'],
      delegate: '0x89D13c596c45E4eE80Af5ae06C727FE9A820ffD0',
    },
    // spec 294 — the SIMPLE demo (apps/demo-web). Unlike the relying apps below, demo-web is a
    // self-contained demo that bootstraps its OWN Smart Agent across SIWE / passkey / social. So its
    // social (OIDC) sign-in is custody-grade (`socialCustody: true`) — the OIDC custodian deploys + signs
    // for the SA directly, giving tri-custody parity with the SIWE/passkey paths. NOT a pattern for true
    // relying apps (which stay login-grade + onboard via the Personal Home).
    {
      client_id: 'demo-web',
      name: 'agenticprimitives demo',
      redirect_uris: ['https://agenticprimitives-demo.pages.dev/', 'http://localhost:5173/'],
      allowed_scopes: ['openid', 'agent'],
      allowed_delegation_templates: ['site-login'],
      delegate: '0x89D13c596c45E4eE80Af5ae06C727FE9A820ffD0',
      socialCustody: true,
    },
    {
      // demo-web-pro (Treasury service-agent story). Uses quick-connect / demo personas locally:
      // Alice + Bob ARE Home demo people, so their Person Smart Agents and custodian signatures come
      // from the Home. The site delegation is unused (web-pro signs userOps + custody typed-data
      // directly via the persona's custodian), but a registered client_id is required by /connect/demo-signin.
      client_id: 'demo-web-pro',
      name: 'agenticprimitives treasury demo',
      redirect_uris: ['https://agenticprimitives-demo-pro.pages.dev/', 'http://localhost:5273/'],
      allowed_scopes: ['openid', 'agent'],
      allowed_delegation_templates: ['site-login'],
      delegate: '0x89D13c596c45E4eE80Af5ae06C727FE9A820ffD0',
    },
    {
      // Game Night (gamenight.faithnet.io; "Pokernight" at poker.faithnet.io until 2026-09-14 — the
      // client id and everything bound to it keep the old name, a product rename is copy and DNS) —
      // a card room where people and AI Smart Agents
      // sit at the same table. It was self-registered first; this CURATED entry supersedes it
      // (static wins, and a member entry cannot shadow one), which is what it needs for two things a
      // self-service registration cannot have:
      //
      //   1. `/connect/demo-signin`. The card room offers this Home's demo people on its own sign-in
      //      page, the way demo-web-pro does — same person, same Smart Agent, real custodian
      //      signatures — so a buy-in in the demo exercises a real authority chain, not a mock.
      //   2. `poker-buyin`. Chips are bought with USDC out of the player's own treasury and returned
      //      to it on cash-out, so the app has to be allowed to ask for a payment mandate. That
      //      template is curated-only, deliberately.
      //
      // localhost:5173 is the Vite dev server: the ceremony cannot run against a dev build without a
      // registered http redirect, and the registry allows plain http on localhost only.
      client_id: 'pokernight',
      name: 'Game Night',
      redirect_uris: ['https://gamenight.faithnet.io/', 'https://poker.faithnet.io/', 'http://localhost:5173/'],
      // `profile` — the scope that lets this app receive the player's HUMAN name (what they are
      // called, not a `<label>.me` handle). It is an already-advertised scope
      // (`.well-known/openid-configuration`) that nothing consumed until now; the Home puts the
      // name on the id_token's `agent_name` claim for scoped clients whose account is nameless, so
      // a table can label a seat instead of rendering `0x1234…abcd`. Registry-gated on purpose: a
      // `scope=` request parameter is attacker-supplied, this entry is curated (same rule as the
      // app's name and logo at consent).
      allowed_scopes: ['openid', 'profile', 'agent'],
      // CLUBS (pokernight `docs/WORKSPACES.md`). A poker night belongs to a group, and that group is
      // a `.workspace` Smart Agent the host custodies — the same shape Field and Gather27 use, and
      // chosen over `.circle` for the same reason: a workspace is what the estate uses when a
      // relying app holds a roster in an agent's vault and gates its own calls on it.
      //
      //   workspace-create        the host charters the club under their own name
      //   workspace-member-invite / workspace-join   the two legs of the single-use membership
      //                           handoff at /connect/workspace-invite
      //   service-agent-wire      the club authorizes the card room's KMS key as its DELEGATE, so
      //                           the club's own agent can act between sessions (the weekly
      //                           invitation goes out when nobody is looking). A wire, never custody.
      //
      // All four are curated-only — `SELF_SERVICE_TEMPLATES` is `['site-login','org-create']` — which
      // is why this entry exists rather than the self-registration the card room started with.
      allowed_delegation_templates: [
        'site-login',
        'poker-buyin',
        'workspace-create',
        'workspace-member-invite',
        'workspace-join',
        'service-agent-wire',
        // A MISSION REGISTERS: an org-create (purpose `mission`) that carries `registry_entry` and ends with
        // the organization listed in the card room's mission registry (`missionRegistryConfig` below).
        'org-create',
        // A CHARACTER IS A PERSON OF YOURS. Taking a part in Mystery Night charters another person agent in
        // the player's OWN home — person-class, `.me`-named, never their default — with a vault of its own
        // for what that character comes to know. Idempotent by name, which is what lets the same character
        // come back for the next game rather than starting over as a stranger with the same face.
        'person-create',
      ],
      // THE MISSION REGISTRY (Game Night `docs/MISSION-REGISTRY.md`): `urn:ap:registry:gamenight-missions`
      // on this chain's AgentRegistryBase, controlled by the card room's registry operator agent. Named
      // here so the org-create ceremony lists into it and nowhere else.
      missionRegistryConfig: { registryId: 'urn:ap:registry:gamenight-missions' },
      delegate: '0x89D13c596c45E4eE80Af5ae06C727FE9A820ffD0',
      // A PERSON AT THE CARD ROOM IS NAMED. The card room addresses a person's agent by its public name and
      // nothing else — the table asks `alice.me` for advice, records her hands to `alice.me`, and hires her
      // coach through `alice.me`'s playbook — so a nameless agent (an email or phone home that never claimed a
      // name) can have no coach and no memory there, however the connect-time defaults went. A person who
      // arrived by email sat down with the house coach and no way to see why (2026-09-13). Claim the name
      // on the way in, once, and everything after it works.
      requireNamedAgent: true,
      // Where the `service-agent-wire` ceremony reads the card room's signing key and hands back the
      // signed wire (`/admin/signer-address`, `/admin/service-wire`). The TABLES worker, because that
      // is the thing that holds the key and reads the club's vault — pokernight has no separate a2a
      // worker, and inventing one to match another app's layout would be shape-matching, not design.
      //
      // NOTE there is deliberately no `operational_delegate` here. That field mints an org→agent
      // OPERATIONAL INTENT grant at org-create so an app can submit endeavor intents; the card room
      // submits none, and a grant nobody redeems is authority sitting there for no reason. The wire
      // above is the rail this app actually needs, and it names its delegate at ceremony time from
      // the service's own answer rather than from this file.
      serviceAgentConfig: {
        a2aBase: process.env.NEXT_PUBLIC_POKERNIGHT_A2A_BASE || 'https://tables.faithnet.io',
      },
      // The caps the ceremony binds into the mandate. `payee` is the Poker Site Treasury on
      // faithchain; `asset` is the chain's test USDC (6dp). A buy-in is at most 200 USDC, a night at
      // most 1000 across at most 5 buy-ins, and the window is a day — a session, not a standing
      // arrangement.
      //
      // `pull`, emphatically NOT `push`. A push ceremony CHARGES as it mints (onboarding.ts's
      // all-custodian charge, gated on `mode !== 'pull'`), which is right for pay-per-read: you
      // authorise and pay in one act. A buy-in is the opposite — the player authorises a ceiling now
      // and the card room takes a buy-in only when they actually sit down. With `push` the ceremony
      // took 200 USDC at the moment of approval, for nothing, and the player then paid a second 200
      // for the real seat. `pull` mints the mandate and moves no money.
      paymentConfig: {
        payee: '0xf6F48aF1f645c70339b2FCF4CD36F5d6c5325671',
        // THE SHEQEL, deployed on faithchain — the card room's own coin and the only currency it
        // settles in (`contracts/src/Sheqel.sol` in the pokernight repo). This line and
        // `new_member.currency.asset` below MUST AGREE: `memberCurrencyPlan` refuses the whole
        // capability while they differ, because opening an account for one token and minting a
        // mandate over another is the failure worth making impossible.
        asset: '0xa14E4a9447607c1233DcE34dB6Ead47C094f6141',
        maxAmountPerCharge: '200000000',
        maxAggregate: '1000000000',
        maxRedemptionsPerWindow: 5,
        windowSeconds: 86400,
        mode: 'pull',
        // ⚠️ PLACEHOLDER — THE POKER SERVICE AGENT'S SA. Who may PRESENT the mandate, as distinct
        // from `payee`, who receives the coin. The house treasury above collects; the card room's
        // service agent is the account that actually holds a signing key and redeems. Until this is
        // filled in the delegate stays the payee, which is byte-for-byte what `mode: 'pull'` minted
        // before this field existed. It MUST NOT be the shared `delegate` above — spend authority
        // granted to that address is granted to every registry entry that names it.
        redeemer: '0x0347e808a0bB7a7a7086a29d853E799f351C04DD',
      },
      // What a player needs to exist BEFORE the card room can do anything with them — declared here
      // so the Home sets it up during account creation instead of sending them on an errand.
      //
      //   personal_treasury: a buy-in is USDC out of the player's own account and a cash-out goes
      //     back into it, so a player with no money account can be dealt in but cannot sit down. The
      //     `poker-buyin` mandate above literally has nowhere to point without one — the connect
      //     silently skipped the payment leg for anyone who hadn't already made a treasury by hand.
      //     It is created NAMELESS: nothing at a poker table needs a global handle for it.
      //   collect_name: a table shows who is sitting at it. A phone sign-up otherwise arrives with
      //     no name of any kind and shows as `0x1234…abcd` to the other players, which is the
      //     complaint. `required` because the seat label is not optional at a card table — the
      //     player types a name once, here, and every app that reads their profile has it after.
      //
      //   currency: chips are Sheqels, this card room's own coin. Declaring it here means one
      //     connect covers all three things a player needs to exist: the account (above), 10,000
      //     Sheqels in it, and the card room's own agent allowed to move them within the caps in
      //     `paymentConfig`. That last one used to be a SECOND full redirect ceremony
      //     (`delegation_template=poker-buyin`) the app sent the player back out on.
      //
      // NOTE for whoever adds the next app: this is the ONLY entry in this registry that carries
      // `new_member`. Leaving the field off is not an oversight anywhere else — it is what keeps
      // those apps' onboarding byte-identical to what it was.
      new_member: {
        personal_treasury: true,
        collect_name: 'required',
        currency: {
          // The deployed Sheqel, identical to `paymentConfig.asset` above and checked against it.
          // This block used to carry the zero address, which is how this registry writes "not
          // deployed" — `memberCurrencyPlan` reads it as "no currency declared" and the whole
          // capability stays off. The token exists now, so the capability is ON for this one app,
          // and the registry tests in `lib/new-member.test.ts` assert that it is on here and off
          // everywhere else.
          asset: '0xa14E4a9447607c1233DcE34dB6Ead47C094f6141',
          name: 'Sheqel',
          plural: 'Sheqels',
          // Sheqel is a 6-decimal token like the chain's other demo assets; `initial_amount` is in
          // its smallest units, so 10000000000 = 10,000 Sheqels. Change BOTH if the deployed token
          // uses different decimals — the figure the player is shown is computed from this pair.
          decimals: 6,
          initial_amount: '10000000000',
          // The card room's chips are play money with a permissionless mint. The Home also PROVES
          // that on chain (a simulated mint) before it seeds anything — see `lib/member-coin.ts`.
          faucet: true,
          spend_grant: true,
        },
      },
    },
    {
      client_id: 'demo-org',
      name: 'Impact',
      redirect_uris: ['https://agenticprimitives-demo-org.pages.dev/', 'http://localhost:5473/'],
      allowed_scopes: ['openid', 'agent'],
      allowed_delegation_templates: ['site-login', 'org-create'],
      // The canonical demo-org delegate SA (ADR-0019). Source of truth — the URL-supplied
      // `delegate` parameter is rejected if it doesn't equal this.
      delegate: '0x89D13c596c45E4eE80Af5ae06C727FE9A820ffD0',
      // logo omitted → consent shows an initial badge (no spoofable logo).
    },
    // spec 236 — "JP Adopt" relying app (demo prototype): JP runs the adoption program;
    // Impact Community holds the data (PII, signed MOU/WEA) in the member's vault and
    // delegates scoped, revocable access. The consent screen reads "JP Adopt is asking
    // to connect" — JP is the program, not a sub-brand of Impact. The literal name of
    // the real underlying organization is NOT used on the live site (demo disclaimer).
    {
      client_id: 'demo-jp',
      name: 'JP Adopt',
      redirect_uris: ['https://agenticprimitives-demo-jp.pages.dev/', 'http://localhost:5573/'],
      allowed_scopes: ['openid', 'agent'],
      allowed_delegation_templates: ['site-login', 'org-create', 'jp-data-access'],
      // TODO: deploy a JP-specific delegate SA + replace here (SEC-003 follow-up — user has
      // deferred per-app delegates for now; the broker still enforces "delegate matches
      // registered" so a future split is a config-only change).
      delegate: '0x89D13c596c45E4eE80Af5ae06C727FE9A820ffD0',
    },
    // spec 250/251 — "Global Switchboard" relying app (demo-gs): a capability/expertise broker.
    // A person signs in (KC individual) or creates a GCO organization (the org holds the GCO
    // role) — both through the shared Global.Church identity, exactly the Phase-2 "one-tap"
    // arrival the Switchboard pilot describes. demo-gs holds no PII; site-login + org-create only.
    {
      client_id: 'demo-gs',
      name: 'Global Switchboard',
      redirect_uris: ['https://agenticprimitives-demo-gs.pages.dev/', 'http://localhost:5673/'],
      allowed_scopes: ['openid', 'agent'],
      allowed_delegation_templates: ['site-login', 'org-create'],
      delegate: '0x89D13c596c45E4eE80Af5ae06C727FE9A820ffD0',
      requireNamedAgent: true,
    },
    // specs 266/267 — "Bible Explorer" relying app: the Verifiable Content Substrate +
    // scripture vertical demo (demo-bible-ontology Worker). Connects via Global.Church
    // identity; site-login + org-create only (no PII held by the broker).
    {
      client_id: 'bible-explorer',
      name: 'Bible Explorer',
      redirect_uris: [
        // faithnet universe (chain 34348) — explorer.faithnet.io, present only when the deploy sets it
        // (same env-gating as field-app). FIRST on purpose: the front-channel sign-out takes the first
        // https URI per client.
        ...(process.env.NEXT_PUBLIC_BIBLE_EXPLORER_ORIGIN ? [process.env.NEXT_PUBLIC_BIBLE_EXPLORER_ORIGIN] : []),
        'https://demo-bible-ontology-production.richardpedersen3.workers.dev/',
        'http://localhost:5673/',
      ],
      allowed_scopes: ['openid', 'agent'],
      // spec 272/243 — `x402-pay`: the member authorizes (once) a capped payment delegation from
      // their person-treasury to the lbsb licensed-scripture treasury, redeemed per paid read (x402).
      allowed_delegation_templates: ['site-login', 'org-create', 'x402-pay'],
      delegate: '0x89D13c596c45E4eE80Af5ae06C727FE9A820ffD0',
      // x402 push: USDC lands at the lbsb-treasury SA; the reader redeems at access time (OPEN delegate).
      // 0.001 USDC/read (1000 atomic, 6-dp mock USDC), 1.0 USDC aggregate cap per delegation.
      paymentConfig: {
        // A DIFFERENT treasury + USDC PER IDENTITY UNIVERSE: the faithnet deploy sets these to
        // lbsb-treasury.impact on faithchain + faithchain's mock USDC; unset = base-sepolia's.
        payee: (process.env.NEXT_PUBLIC_LBSB_TREASURY || '0x17320bF2DAe8820157530c634B9bB76f6Eb72004') as `0x${string}`,
        asset: (process.env.NEXT_PUBLIC_LBSB_USDC || '0x6cfF706bA1461a9ef9F5aaf8f1581301805FbF92') as `0x${string}`,
        maxAmountPerCharge: '60000', // 0.06 USDC — covers the largest tier (Plus); the UI picks the amount
        maxAggregate: '6000000',     // 6 USDC across the delegation's life
        maxRedemptionsPerWindow: 1000,
        windowSeconds: 3600,
        mode: 'push',
      },
    },
    // demo-corpus relying app — connects via Global.Church identity; site-login + org-create
    // (no PII held by the broker). aud = client_id; the allowed origin is derived from the
    // exact-match redirect_uri (CN-1) by `src/lib/oidc-clients.ts`.
    {
      client_id: 'demo-corpus',
      name: 'Demo Corpus',
      redirect_uris: [
        // faithnet universe — corpus.faithnet.io, env-gated like the explorer above; first on purpose.
        ...(process.env.NEXT_PUBLIC_DEMO_CORPUS_ORIGIN ? [process.env.NEXT_PUBLIC_DEMO_CORPUS_ORIGIN] : []),
        'https://demo-corpus-production.richardpedersen3.workers.dev/',
      ],
      allowed_scopes: ['openid', 'agent'],
      // spec 272 recurring — `subscription-collect`: the corpus OWNER redeems DUE subscribers' standing
      // pull mandates (owner-online, no held key), signed as the collection treasury they custody.
      // spec 266 — `content-signer`: the owner authorizes each content issuer's Cloud-KMS signing key.
      allowed_delegation_templates: ['site-login', 'org-create', 'subscription-collect', 'content-signer'],
      delegate: '0x89D13c596c45E4eE80Af5ae06C727FE9A820ffD0',
      // The owner-custodied lbsb collection treasury (= lbsb-treasury.impact, the pull mandates' delegate)
      // and the content service exposing the owner-gated due/collected endpoints.
      collectionConfig: {
        // Per identity universe, same as the explorer's paymentConfig: the faithnet deploy names
        // lbsb-treasury.impact on faithchain, faithchain's mock USDC and scripture.faithnet.io.
        treasury: (process.env.NEXT_PUBLIC_LBSB_TREASURY || '0x17320bF2DAe8820157530c634B9bB76f6Eb72004') as `0x${string}`,
        asset: (process.env.NEXT_PUBLIC_LBSB_USDC || '0x6cfF706bA1461a9ef9F5aaf8f1581301805FbF92') as `0x${string}`,
        edition: 'lbsb',
        a2aBase: process.env.NEXT_PUBLIC_SCRIPTURE_A2A_BASE || 'https://demo-bible-a2a-production.richardpedersen3.workers.dev',
      },
    },
    // UUPG+ Alliance Engagement Tracker (agentictrustlabs/uupg — the ported demo-uupg) — connects via
    // Global.Church identity; site-login + org-create (the tracker's alliance/org ceremonies hand off
    // to the Home). No PII held by the broker; aud = client_id; allowed origin derived from the
    // exact-match redirect_uri (CN-1) by `src/lib/oidc-clients.ts`.
    {
      client_id: 'uupg-tracker',
      name: 'UUPG+ Tracker',
      redirect_uris: [
        'https://uupg.richardpedersen3.workers.dev/',
        // verifiable-content-demo apps/demo-uupg (the original) — repointed onto this broker.
        'https://demo-uupg-production.richardpedersen3.workers.dev/',
        'https://demo-uupg.richardpedersen3.workers.dev/',
        'https://demo-uupg-production.global-church.workers.dev/',
        // uupg apps/tracker — the hotspot workspace (same product, its own Worker; dev on :8799).
        'https://hotspot-tracker.richardpedersen3.workers.dev/',
        'http://127.0.0.1:8797/',
        'http://localhost:8797/',
        'http://127.0.0.1:8799/',
        'http://localhost:8799/',
      ],
      allowed_scopes: ['openid', 'agent'],
      allowed_delegation_templates: ['site-login', 'org-create'],
      delegate: '0x89D13c596c45E4eE80Af5ae06C727FE9A820ffD0',
    },
    // Global.Church Engage (engage.global.church) — GC's engagement dashboard, NOT the `engage-app`
    // above (that is agentictrustlabs/engage, a different product). Server-side sign-in in the
    // openbook-tyndale shape: /api/auth/start 307s here with PKCE + site-login, the code lands at
    // /api/auth/callback and is exchanged server-side; the id_token is the session. `profile` so the
    // member's human name can label the account. No email claim — engage keys identity on `sub`.
    // Re-registers verbatim on gcid.me when GC ID launches.
    // `org-create` for the reason source-publishing has it: an ORGANIZATION that files needs, commitments and
    // engagement attestations in engage is one the person holds at their Home, never a row GC grants. The person
    // creates or picks it here (chooser mode) and engage reads who belongs to it from /connect/related-orgs.
    {
      client_id: 'gc-engage',
      name: 'Global.Church Engage',
      redirect_uris: [
        'https://engage.global.church/api/auth/callback',
        'http://localhost:3000/api/auth/callback',
      ],
      allowed_scopes: ['openid', 'profile', 'agent'],
      allowed_delegation_templates: ['site-login', 'org-create'],
      delegate: '0x89D13c596c45E4eE80Af5ae06C727FE9A820ffD0',
    },
    // Global.Church Platform (platform.global.church) — GC's church explorer, developer portal
    // (API keys) and admin. Same server-side sign-in as `gc-engage` above: /api/auth/start 307s here
    // with PKCE + site-login, the code is exchanged at /api/auth/callback, the id_token is the
    // session. `profile` so the member's human name can label the account and the admin user list.
    // No email claim — platform keys identity on `sub`. Local dev on :3001 so it runs beside engage.
    // Re-registers verbatim on gcid.me when GC ID launches.
    // `org-create` as on `gc-engage`: platform's organization page sends the person here to create or pick the
    // organization they hold, and reads its members from the Home.
    {
      client_id: 'gc-platform',
      name: 'Global.Church Platform',
      redirect_uris: [
        'https://platform.global.church/api/auth/callback',
        'http://localhost:3001/api/auth/callback',
      ],
      allowed_scopes: ['openid', 'profile', 'agent'],
      allowed_delegation_templates: ['site-login', 'org-create'],
      delegate: '0x89D13c596c45E4eE80Af5ae06C727FE9A820ffD0',
    },
    // Engagement Campaign Studio (uupg apps/campaign) — org-scoped ask over demo-a2a needs a
    // session whose `aud` is THIS client_id. Borrowing `uupg-tracker` mints a valid token that
    // demo-a2a then refuses as aud mismatch. Same demo delegate as the other uupg apps.
    {
      client_id: 'campaign-studio',
      name: 'Engagement Campaign Studio',
      redirect_uris: [
        'https://campaign-studio.richardpedersen3.workers.dev/',
        'http://127.0.0.1:8801/',
        'http://localhost:8801/',
      ],
      allowed_scopes: ['openid', 'agent'],
      allowed_delegation_templates: ['site-login', 'org-create'],
      delegate: '0x89D13c596c45E4eE80Af5ae06C727FE9A820ffD0',
    },
    // Single-organization site (agentictrustlabs/uupg apps/org) — ONE Worker serving a dedicated
    // per-org website; the org is resolved from the hostname (or `?org=<label>` on the workers.dev
    // and local-dev origins, which is why those redirect_uris are enough for now). site-login only.
    // NOTE: redirect_uris are EXACT-match (CN-1) — production per-org subdomains
    // (`https://<label>.<zone>/`) must each be registered here explicitly, or clientAllowsRedirect
    // needs a deliberate wildcard-host extension for this client before subdomain routing goes live.
    {
      client_id: 'org-site',
      name: 'Organization Site',
      redirect_uris: ['https://uupg-org.richardpedersen3.workers.dev/', 'https://org.richardpedersen3.workers.dev/', 'http://127.0.0.1:8798/', 'http://localhost:8798/'],
      allowed_scopes: ['openid', 'agent'],
      allowed_delegation_templates: ['site-login'],
      delegate: '0x89D13c596c45E4eE80Af5ae06C727FE9A820ffD0',
    },
    // New City AI family/advisor portal (newcitycase repo, apps/portal) — wealth reporting on the
    // substrate; site-login + org-create (FR-48: the connecting user creates/selects a user-custodied
    // family org at onboarding). Local dev/e2e shares port 8798 with org-site (distinct client_id, so
    // no ambiguity — the RP always sends its own client_id). Delegate is the shared demo delegate SA
    // for now; replace when the portal mints its own service SA.
    {
      client_id: 'newcity-portal',
      name: 'New City AI Portal',
      redirect_uris: [
        'https://newcity-portal.richardpedersen3.workers.dev/',
        'http://127.0.0.1:8798/',
        'http://localhost:8798/',
      ],
      allowed_scopes: ['openid', 'agent'],
      allowed_delegation_templates: ['site-login', 'org-create'],
      delegate: '0x89D13c596c45E4eE80Af5ae06C727FE9A820ffD0',
    },
    // OpenBook × Tyndale (openbook-tyndale.vercel.app) — Tyndale Open Bible Dictionary demo with a
    // server-side "Sign in with Home" flow (its /api/home/start 307s here with PKCE + template=site-login;
    // the code lands at /api/home/callback, exchanged server-side). site-login only; no PII at the broker.
    {
      client_id: 'openbook-tyndale',
      name: 'OpenBook × Tyndale',
      redirect_uris: [
        'https://openbook-tyndale.vercel.app/api/home/callback',
        'http://localhost:3000/api/home/callback',
      ],
      allowed_scopes: ['openid', 'agent'],
      allowed_delegation_templates: ['site-login'],
      delegate: '0x89D13c596c45E4eE80Af5ae06C727FE9A820ffD0',
    },
    // Source Publishing / OpenBook (verifiable-content-demo apps/demo-publishing-*) — stewards publish
    // complete works from their own Home library; publishing is the library's `publish` release over the
    // work manifest, archived by the site. site-login only; no PII at the broker. Quick connect (the sample
    // people) needs this client_id to exist, and the popup/redirect ceremony needs the exact redirect_uri.
    // Lives on the FAITHNET estate (publishing.faithnet.io); the workers.dev origin is its fallback host.
    // FIRST on purpose: the front-channel sign-out takes the first https URI per client.
    {
      client_id: 'source-publishing',
      name: 'Source Publishing',
      redirect_uris: [
        'https://publishing.faithnet.io/',
        'https://demo-publishing-web.richardpedersen3.workers.dev/',
        'http://localhost:5177/',
      ],
      // `profile`: the person's HUMAN name rides on `agent_name` for a nameless account, so the one-time
      // "About you" step starts from what they are called rather than 0x…. Registry-gated like pokernight's.
      allowed_scopes: ['openid', 'profile', 'agent'],
      // The email rides the id_token too (registry-gated, consent line added at the grant): the publisher profile's
      // "email — stays in your library" starts from the one the person signed in with instead of an empty box.
      idTokenClaims: ['email'],
      // The app reads the person's CONTACT PROFILE (name, email) from their vault in one call under this grant —
      // reference data it never stores (agent-rules/vault-is-the-record); revocable by the person alone.
      read_grant: { resources: ['vault:impact-profile'] },
      // org-create: a publisher's ORGANIZATION is chosen from the Home roster, never typed; establishing
      // a new one is the Home's org-create ceremony (chooser mode), launched from the wizard's "About you".
      // Spec 412 W5 — `ask-as-me`: the person's wire to the publishing gateway's OWN key, pinned to harness.ask.
      // Publishing a work asks HER AGENT to save the text and the manifest into her Library and to mint the release
      // — her agent writes as her; the app never holds a write grant on her vault (spec 341 §4.3b stands).
      allowed_delegation_templates: ['site-login', 'org-create', 'ask-as-me'],
      delegate: '0x89D13c596c45E4eE80Af5ae06C727FE9A820ffD0',
      // The key demo-publishing-a2a signs A2A-Session assertions with (`PUBLISHING_PRIVATE_KEY` on that Worker);
      // `NEXT_PUBLIC_PUBLISHING_ASK_DELEGATE` for another estate. It must equal that Worker's key or the wire names a
      // key the gateway cannot present.
      ask_delegate: (process.env.NEXT_PUBLIC_PUBLISHING_ASK_DELEGATE || '0x94E58bE2CfdD0418E03059BC8596E6f20579c77b') as `0x${string}`,
      libraryFolders: ['publishing'],
    },
    // OpenBook READER (verifiable-content-demo apps/demo-openbook-reader) — readers discover works across publishers
    // through the OpenBook Registry, read with in-browser checks, verify quotes, and buy access. Sign-in is asked only
    // at the moments of value (keep a verified citation, buy access, record what they read); browsing is anonymous.
    // site-login only for now; no PII at the broker beyond the name on the token (`profile`). FIRST https URI on purpose.
    {
      client_id: 'openbook-reader',
      name: 'OpenBook Reader',
      redirect_uris: [
        'https://reader.faithnet.io/',
        'https://demo-openbook-reader-production.richardpedersen3.workers.dev/',
        'http://localhost:5178/',
      ],
      allowed_scopes: ['openid', 'profile', 'agent'],
      // Spec 412 W5 — `ask-as-me`: what a reader reads, verifies and buys is written into THEIR OWN vault by THEIR agent
      // (a private `openbook/engagement` record per event), asked as them under this wire; the app keeps counts, not people.
      allowed_delegation_templates: ['site-login', 'ask-as-me'],
      delegate: '0x89D13c596c45E4eE80Af5ae06C727FE9A820ffD0',
      // The reader Worker's asking key (`READER_ASK_PRIVATE_KEY` on demo-openbook-reader-production) — a revocable delegate.
      ask_delegate: (process.env.NEXT_PUBLIC_OPENBOOK_READER_ASK_DELEGATE || '0xAB29Fb55ded14d3f917e65774988C019068Fc835') as `0x${string}`,
      libraryFolders: ['openbook'],
    },
  ],
  // Consent disclosure per template — the human-readable can/cannot shown at the permission
  // step. The caveats themselves are contract-enforced (spec 230); this is presentational.
  delegationTemplates: {
    'site-login': {
      canDo: ['Sign in as you in the missional community', 'Read your community profile'],
      cannotDo: ['Move your funds', 'Add new sign-in methods', 'Change your recovery'],
      expiryDays: 365,
    },
    'org-create': {
      canDo: ['Set up an organization under your name', 'View approved org records for this session'],
      cannotDo: ['Change organization access', 'Add members or move funds', 'Act outside this permission'],
      expiryDays: 365,
    },
    // NAMES NO APP. These lines are rendered VERBATIM by `ConsentSheet` — `fmt` is not applied to
    // `canDo` / `cannotDo` — so a product name written here is shown to every app that requests the
    // template. It said "Create a Field Workspace" and "Authorize Field to act as that workspace",
    // which is what a Poker Night host was shown while chartering their poker club: the wrong
    // product named on the one screen whose whole job is to say who is being trusted with what.
    //
    // "this app" is correct for all of them, and the sheet already shows the asking app's name and
    // domain directly above these bullets, so nothing is lost by not repeating it here.
    //
    // TWO AGENTS, SAID AS TWO (2026-10-02, the owner's rule — `lib/workspace-governor.ts`): a workspace agent is a
    // service and holds no members, so the ceremony charters the ORGANIZATION that governs the workspace first and
    // the workspace under it. The roster is the organization's; the workspace keeps its records. A sheet that
    // said "a workspace" while two agents were being started under the person's name would be the untruth this
    // copy exists to avoid.
    'workspace-create': {
      canDo: [
        'Create an organization under your name, and the workspace it governs',
        'Keep who belongs on the organization, and the workspace’s shared records in its own vault',
        'Authorize this app to act as that workspace, revocably',
      ],
      cannotDo: [
        'Take custody of the organization or the workspace agent away from you',
        'Move funds, or touch your sign-in methods or recovery',
        'Copy records out of steward vaults',
      ],
      expiryDays: 365,
    },
    'workspace-member-invite': {
      canDo: [
        'Invite the person you named into the organization that governs this workspace',
        'Let them read this workspace, revocably',
        'Hold that access for them until they join',
      ],
      cannotDo: [
        'Make them a steward, or change who governs the workspace',
        'Touch their home, their vault, or their sign-in',
        'Move funds',
      ],
      expiryDays: 365,
    },
    'workspace-join': {
      canDo: [
        'Join the organization that governs this workspace, as a member',
        'Add this workspace to the places you can work',
        'Accept the access its steward set aside for you',
      ],
      cannotDo: [
        'Give the workspace anything from your own vault',
        'Make you a steward of it',
        'Move funds, or touch your sign-in methods or recovery',
      ],
      expiryDays: 365,
    },
    // spec 272/243 — pay-per-access for licensed content. Your personal treasury authorizes capped,
    // per-read charges to the content's treasury; you can revoke anytime. The cap + payee are
    // contract-enforced (PaymentEnforcer), not just disclosure.
    'x402-pay': {
      canDo: [
        'Pay a small, capped fee from your personal treasury for each licensed read',
        'Send those payments only to this content provider’s treasury',
      ],
      cannotDo: [
        'Charge more than the per-read cap or the total you approved',
        'Move funds to anyone other than this provider',
        'Touch your sign-in methods or recovery',
      ],
      expiryDays: 365,
    },
    // Pokernight — a table buy-in. Scoped like x402-pay (capped, one payee) but bounded to a SESSION
    // rather than a year: a night at a table is the unit of consent, so this expires in a day and the
    // player re-authorizes next time. The cap the player approves covers the buy-in plus any rebuys
    // they allow; chips still at the table when they leave are returned to the same treasury.
    'poker-buyin': {
      // NAMES NO CURRENCY. It used to say "Move USDC", which stopped being true the day the card room
      // cut over to its own coin — and a consent screen that names the wrong money at the moment
      // somebody approves spending is the worst place in the product to be out of date. The amounts
      // and the coin come from `currencyConsentLines`, generated from `new_member.currency`, so
      // there is now exactly one place that says how much and in what.
      canDo: [
        'Take from the money account you pick, up to the amount you approve, to put chips on the table',
        'Do that again for a rebuy, within that same approved total',
        'Put your remaining chips back into the same account when you leave the table',
      ],
      cannotDo: [
        'Take more than the total you approved, or keep taking it after tonight’s window closes',
        'Send it anywhere but the card room',
        'Touch your sign-in methods or recovery',
      ],
      expiryDays: 1,
    },
    // spec 272 recurring — the corpus OWNER collects due subscriptions: signs, with their own credential,
    // the redemption of each due subscriber's standing pull mandate as the collection treasury they custody.
    'subscription-collect': {
      canDo: [
        'Charge subscribers whose period is due, using the standing mandate each one already authorized',
        'Send each charge only to your content treasury, capped by that mandate',
      ],
      cannotDo: [
        'Charge more than a subscriber authorized, or charge a non-subscriber',
        'Move funds anywhere other than your content treasury',
        'Touch sign-in methods or recovery',
      ],
      expiryDays: 1,
    },
    // spec 266 — the corpus OWNER authorizes each content issuer's Cloud-KMS signing key: signs, with their
    // own credential, a delegation binding each issuer SA (e.g. lbsb.impact) → its KMS content-signing key.
    'content-signer': {
      canDo: [
        'Authorize an HSM-backed Cloud KMS key to sign content on behalf of issuers you control (e.g. lbsb.impact)',
        'Bind each authorization to a specific issuer + key, revocable later',
      ],
      cannotDo: [
        'Expose or move any signing key (the key never leaves the HSM-backed Cloud KMS)',
        'Authorize signing for an issuer you do not custody',
        'Touch sign-in methods, funds, or recovery',
      ],
      expiryDays: 1,
    },
    // agent-rule `service-agent-signing.md` — you authorize a service's HSM-backed KMS key to act AS
    // an agent you custody (e.g. skills-agent.impact), for ONE kind of message, revocably. The
    // service never holds anything that controls the agent.
    // Spec 397 — the Home MCP's ask wire: what Claude (or any assistant) holds when it connects as a client of you.
    'ask-as-me': {
      canDo: [
        'Put a question to your agent as you — your records, your organizations, your playbook',
      ],
      cannotDo: [
        'Sign anything: every act still waits for your signature at this Home',
        'Move funds, or touch your sign-in methods or recovery',
        'Read anything your agent would not show you',
      ],
      expiryDays: 30,
    },
    // Spec 397 §11 — the act set: one standing wire per act YOU checked, each revocable on its own; a payment wire
    // is from your treasury to one payee with a cap. The ceremony lists the acts; this is the frame around them.
    'act-as-me': {
      canDo: [
        'Run the acts you check below without a second signature, for 30 days',
        'Pay the one payee you name, up to the cap you set, from the treasury you choose',
      ],
      cannotDo: [
        'Run any act you did not check — those still wait for your signature at this Home',
        'Pay anyone else, more than the cap, or from any other treasury',
        'Touch your sign-in methods, your recovery, or your other grants',
      ],
      expiryDays: 30,
    },
    'service-agent-wire': {
      canDo: [
        'Let this service act as an agent you custody, for one specific kind of request',
        'Bind that permission to the service’s HSM-backed key, revocable by you at any time',
      ],
      cannotDo: [
        'Take custody of the agent, or act as it for anything else',
        'Expose or move any signing key (it never leaves the HSM-backed Cloud KMS)',
        'Move funds, or touch your sign-in methods or recovery',
      ],
      expiryDays: 90,
    },
    // spec 247 — JP's adoption program reads + writes the data it holds for you (your
    // profile + program records) in YOUR vault, through this scoped grant. The records
    // stay in your vault; JP holds the permission, not a copy of your data.
    'jp-data-access': {
      canDo: [
        'Sign in as you in the missional community',
        'Read your profile + adoption records from your vault',
        'Record your MOU, adoption, and program updates into your vault, on your behalf',
      ],
      cannotDo: [
        'Move your funds',
        'Add new sign-in methods or change your recovery',
        'Share your records with anyone else without a new permission',
      ],
      expiryDays: 365,
    },
  },
  // Member-facing copy — the lexicon (docs/portal-lexicon.md). {name} = the member's name;
  // {app} = the missional-community app asking for permission.
  copy: {
    // Arrival into your home.
    // Env-overridable so a deployment can name its own front door (Global.Church: "Sign in with your Great
    // Commission ID (GCID)", Paul 2026-10-08). Unset = the original copy.
    arrivalTitle: process.env.NEXT_PUBLIC_ARRIVAL_TITLE || 'Welcome to your Impact Community Home',
    enrollSub: process.env.NEXT_PUBLIC_SIGN_IN_LINE || 'Sign in, then you’ll return.',
    arrivalBody:
      "A place of your own in the missional community — where you oversee what you help lead, manage what you steward, and protect what's entrusted to you.",
    overviewTitle: "Here's how you'll get set up",
    // ① Secure your home (passkey + found it). The passkey path has two device gestures: create the
    // key (portalStepCreateCta) then approve the setup with it (portalStepCta). Spec 255 — distinct
    // labels so the second OS prompt is clearly NOT a repeat of the first.
    portalStepTitle: 'Secure your home',
    portalStepValue: 'A home of your own that only you can open — using just this device, no password to lose.',
    portalStepCreateCta: 'Create your passkey',
    portalStepCta: 'Approve my setup',
    portalStepBusy: 'Securing your home…',
    portalStepReceipt: 'Your home is secured — only you can open it',
    // Receipt after gesture 1 (passkey created) — spec 255.
    portalKeyCreatedReceiptTitle: 'Passkey created — your key is ready',
    portalKeyCreatedReceiptBody: "This device now holds a key that proves it's you. Nothing left this device.",
    // ② Register your name (rides with ①).
    communityStepTitle: 'Register your name',
    communityStepValue: 'Your name in the missional community — so the community and its apps can find you.',
    communityStepReceipt: "You're registered as {name} — the missional community can find you",
    // ③ Give an app permission to your resources.
    authorizeStepTitle: 'Allow {app}?',
    authorizeStepValue: 'A specific, revocable permission for {app} to act for you. You decide what it can touch — and can take it back anytime.',
    authorizeStepCta: 'Allow {app}',
    authorizeStepBusy: 'Granting permission to {app}…',
    authorizeStepReceipt: 'Permission granted — {app} can do only what you allowed',
    // Your home (signed in).
    portalTitle: '{name} · your home',
    portalWelcome: 'Welcome to your home',
    portalYouLabel: 'This is you',
    portalManageHeading: 'What you steward',
  },
};

/** The active white-label for this deployment. */
/**
 * Templates whose ceremony ALSO mints a capped payment delegation from the member's treasury.
 *
 * This used to be a bare `template === 'x402-pay'` at each call site, which quietly meant any other
 * payment template completed as an ordinary sign-in and returned no mandate — the app got a session
 * and nothing to spend under, with no error to explain it. Adding a template here is the one place
 * that decides it; the entry still has to carry a `paymentConfig` for the caps.
 */
export const PAYMENT_TEMPLATES: readonly string[] = ['x402-pay', 'poker-buyin'];

export function isPaymentTemplate(template: string | null | undefined): boolean {
  return template != null && PAYMENT_TEMPLATES.includes(template);
}

export const whitelabel: WhiteLabelConfig = faithImpact;

/** Interpolate {name} / {app} (and any {token}) into a copy string. Missing tokens stay literal. */
export function fmt(template: string, vars: Record<string, string | undefined> = {}): string {
  return template.replace(/\{(\w+)\}/g, (m, k: string) => vars[k] ?? m);
}

export type { WhiteLabelConfig, WhiteLabelCopy, RelyingApp, ManageableAgent, DelegationTemplate, NewMemberOnboarding, MemberCurrency } from './schema';
