// White-label config schema (spec 234 §5/§11). The ONE place a deployment's
// identity, copy, and enabled surfaces live — consumed by the generic Experience
// Layer. Vertical/faith content belongs HERE (app level), never in packages
// (ADR-0021). Build-time only for now; a runtime/on-chain adapter is W4.
//
// All fields are plain data so a future runtime config can serialize them. Copy
// strings may contain {name} / {app} tokens, interpolated by `fmt` (config.ts).

/** A relying app registered with this trust site (the OIDC client registry, configured). */
export interface RelyingApp {
  client_id: string;
  /** Exact-match redirect URIs (no substring/prefix — CN-1). */
  redirect_uris: string[];
  allowed_scopes: string[];
  /** Delegation caveat templates this client may request (the template fixes the caveats). */
  allowed_delegation_templates: string[];
  /** OPTIONAL — the app's dedicated service SA for OPERATIONAL INTENT grants (org → agent). When set,
   *  org-create also mints that grant so the app can submit endeavor intents to the org's A2A endpoint
   *  directly instead of proxying through Home. MUST NOT be `delegate`: that address is shared by
   *  several registry entries, and operational authority granted to it is granted to all of them. */
  operational_delegate?: string;
  /** OPTIONAL — a scoped `org → app workspace agent` VAULT READ grant, minted at the org-connect
   *  ceremony (create AND select-existing) alongside the operational-intent grant. For apps whose
   *  workspace agent reads ONE record family from each member org's vault in place (a grant, never
   *  a copy — e.g. Gather27's `vault:gather27:listing`). Minted at the ceremony because that is the
   *  only moment every custody family (KMS / passkey / wallet / demo) can sign as the org — a
   *  relying app never holds the org's key, and persona-sign covers demo accounts only.
   *  `delegate` MUST be the app's dedicated workspace/service SA, never the shared registry
   *  `delegate` (same reasoning as `operational_delegate`). */
  org_read_grant?: {
    delegate: `0x${string}`;
    server: string;
    resources: string[];
  };
  /** OPTIONAL — spec 341 §4.3b / 412: a per-app READ GRANT minted at connect. A scoped, revocable delegation from the
   *  person to the interactions service SA naming these record families (`vault:impact-profile`, say), stored on the
   *  person's own object under this client id; the app then reads those records in ONE call (`record.get` under its
   *  own bearer), no harness, no model — and the person revokes it alone under Connected assistants / App grants.
   *  Read ONLY by construction (`issueReadGrant`); a write is never on this rail. Absent means none, which is what
   *  every client gets today. Turns something ON — review it hardest. */
  read_grant?: { resources: readonly string[] };
  /** OPTIONAL — spec 345. A `delegator = delegate = personSA` grant scoped to the person's OWN
   *  vault record family, minted in the SAME plain sign-in ceremony every relying app already
   *  runs (`givePermission` / template `site-login`) — no org, no team, no stewardship, no
   *  `impact-relationships` write. The resources/ops here are the ONLY scope a self-vault grant
   *  for this client can ever carry; a relying app names its `client_id`, never the scope itself. */
  self_vault_grant?: {
    server: string;
    resources: string[];
    ops: ('read' | 'write')[];
  };
  /** OPTIONAL — what Home sets up for the person on a plain sign-in BEYOND the grant itself. Absent
   *  means everything, which is exactly what every client gets today; a client may only turn a leg
   *  OFF, never widen one. `communityMessaging: false` skips the community-messaging wire (and the
   *  related-orgs read that only feeds it) for an app that registers no messaging capability. */
  provisioning?: { communityMessaging?: false };
  /** OPTIONAL — `'with-self-vault'` lets the plain sign-in REUSE its standing grant even though the
   *  client declares a self_vault_grant. Both approved digests (site + self-vault) are fixed for a
   *  given client, so the on-chain approval userOp is identical every time; reusing skips it. Absent
   *  keeps the existing rule: a self-vault ceremony is per-connect. /oidc/grant re-verifies on every
   *  use either way, so this is never a bypass. */
  standingGrant?: 'with-self-vault';
  /** OPTIONAL — private contact claims this client's id_token may carry, beyond identity. Absent
   *  means none, which is what every client gets today.
   *
   *  NOTE THE POLARITY. Its two neighbours above can only turn a leg OFF; this one turns something
   *  ON, so it is the field to look at hardest in review. Naming a claim here is the ONLY way an app
   *  receives it, and it still does not produce the value: the email lives in the member's own
   *  encrypted vault, the broker cannot decrypt it, and it reaches the token only because the
   *  member's own session handed it over (the `profile_name` rail — see connect-profile-name.ts).
   *  A client the member registered themselves can never carry this: those are rebuilt field by
   *  field in relying-clients.ts and this field is not among them. */
  idTokenClaims?: readonly 'email'[];
  /** App logo for the consent screen — comes from THIS registered config, never a request
   *  param (anti-spoof). Optional; falls back to an initial badge. */
  logo?: string;
  /** Friendly app name shown at consent (e.g. "Impact"); falls back to the host. From this
   *  registered config only — never a request param (anti-spoof). */
  name?: string;
  /** OPTIONAL — one plain line saying what the app is for, shown under its name where the consent
   *  sheet introduces it. Same provenance rule as `name`: registered config only, never a request
   *  param. Absent (every client but the ones that set it) renders exactly as before. */
  description?: string;
  /** OPTIONAL — this client's OWN consent wording, in place of the shared defaults. See
   *  {@link ClientConsentCopy}. Absent means the shared `delegationTemplates` / `copy`, unchanged. */
  consent?: ClientConsentCopy;
  /** OPTIONAL — this client's OWN look for its sign-in window. See {@link ClientTheme}. Absent means
   *  the Home's own look, unchanged. */
  theme?: ClientTheme;
  /** The CANONICAL relying-site delegate SA address for this client (ADR-0019). This is the
   *  ONLY delegate the broker will mint a grant for; the URL-supplied `delegate` is
   *  treated as untrusted hint and MUST match this. Address format: 0x-prefixed 20-byte hex.
   *  (SEC-001 closure — the broker no longer accepts attacker-chosen delegates.) */
  delegate: `0x${string}`;
  /** Spec 397 — the key an `ask-as-me` wire names for THIS client when it is not `delegate`: an app that
   *  holds a site delegate for sign-in but asks the person's agent from a DIFFERENT key (a Worker's own
   *  custody key that signs `A2A-Session` assertions). Absent ⇒ `delegate`, as the Home MCP's entry has it. */
  ask_delegate?: `0x${string}`;
  /** Spec 412 — the top-level Library folders THIS app writes into a person's vault (`publishing/…`, `field/…`), so the
   *  Library can say which app a folder belongs to instead of leaving a bare word. Declared by the app's registration —
   *  the app knows where it writes — never inferred from a name. */
  libraryFolders?: readonly string[];
  /** spec 294 — when true, a social (OIDC) sign-in under THIS client_id yields a KMS-CUSTODIED
   *  Smart Agent directly (custody-grade), instead of the default login-grade relying-app path
   *  where members onboard via the Personal Home. A deliberate, registered exception for
   *  SELF-CONTAINED demos (e.g. demo-web) that bootstrap their own SA across SIWE/passkey/social —
   *  NOT for true relying apps (demo-org/jp/gs stay login-grade). Default false/undefined. */
  socialCustody?: boolean;
  /** Where a reply to mail Home sends FOR this app (its host invites) should go — the app's own inbox, not the
   *  Home's no-reply sender. Absent = no Reply-To, as before. */
  replyTo?: string;
  /** When true, this relying app cannot authorize a nameless person Smart Agent. Empty `agent_name`
   *  requests must collect/claim a unique Impact name before granting. */
  requireNamedAgent?: boolean;
  /** OPTIONAL — which sign-in methods the enroll screen OFFERS for this client, in the order given.
   *  Absent means all of them, which is what every client did before this existed and still does.
   *
   *  This narrows the DISPLAY only. Nothing is removed from the broker: every method still works,
   *  a home already made with a passkey still signs in, and the returning-member lane
   *  (`SignInView`) deliberately ignores this — an email- or phone-custodied home has to be able to
   *  get back in however it was made. Curating here is a product decision about what to put in
   *  front of a NEW person for one app, never a statement about what the substrate supports. */
  signInMethods?: readonly ('social' | 'email' | 'phone' | 'passkey' | 'name')[];
  /** x402 payment params for the `x402-pay` template (spec 272/243). Present only on clients that
   *  sell paid content. The home mints a `person-treasury → payee` PaymentEnforcer delegation with
   *  these caps; amounts are atomic-unit strings (plain data / JSON-serializable). `mode`: 'push'
   *  (x402 — OPEN delegate, the reader redeems at access) | 'pull' (delegate = payee, the provider
   *  redeems on its own schedule — subscriptions/metered post-pay). Defaults to 'push'. */
  paymentConfig?: {
    payee: `0x${string}`;
    asset: `0x${string}`;
    maxAmountPerCharge: string;
    maxAggregate: string;
    maxRedemptionsPerWindow?: number;
    windowSeconds?: number;
    mode?: 'push' | 'pull';
    /** OPTIONAL — WHO MAY PRESENT THE MANDATE, when that is not the payee.
     *
     *  `mode` answers WHEN money moves; it was also being made to answer WHO may collect, because the
     *  mandate's delegate was derived from it alone (`pull ? payee : OPEN`). Those are two questions.
     *  A card room's coin lands in the house treasury (the payee) but the account that PRESENTS the
     *  mandate is the app's service agent — it holds the signing key, the house treasury does not —
     *  and there was no way for that app to say so: naming its service agent as the payee would have
     *  sent the money to the wrong account, and leaving it as the payee produced a mandate nobody
     *  could redeem. So the collecting account and the redeeming account get their own fields.
     *
     *  DEFAULTS TO THE PAYEE (i.e. exactly today's `pull` behaviour) and is ignored on `push`, whose
     *  delegate is OPEN by construction — so every existing entry is unaffected. MUST be the app's
     *  DEDICATED service SA, never the shared registry `delegate`: spend authority granted to that
     *  address is granted to every entry that names it (same rule as `operational_delegate`). */
    redeemer?: `0x${string}`;
  };
  /** spec 272 recurring — for an OWNER app (e.g. demo-corpus) with the `subscription-collect` template:
   *  where the owner-online collection ceremony redeems DUE subscribers' pull mandates. `treasury` is the
   *  owner-custodied collection treasury (= the pull mandates' delegate/payee, e.g. lbsb-treasury.impact);
   *  `a2aBase` is the content service exposing the owner-gated /admin/subscriptions/{due,collected}. */
  collectionConfig?: {
    treasury: `0x${string}`;
    asset: `0x${string}`;
    edition: string;
    a2aBase: string;
  };
  /** Where the `service-agent-wire` ceremony reads the service's signing key and hands back the
   *  signed wire. Its own field rather than `collectionConfig` because nothing here is payment:
   *  this is the agent-signing rail (agent-rules/service-agent-signing.md). */
  serviceAgentConfig?: {
    a2aBase: string;
  };
  /** A relying app that keeps a KIT-BUILT REGISTRY (spec 279) its organizations list into: an `org-create` that
   *  carries `registry_entry` ends with the org registered there (`src/lib/mission-registry.ts`). The registry
   *  id is CURATED here, never taken from the request — a write signed by the org's own account must not be
   *  steerable into somebody else's registry. */
  missionRegistryConfig?: {
    registryId: string;
  };
  /** What a member of THIS app is set up with the first time they connect — see {@link NewMemberOnboarding}.
   *
   *  ABSENT MEANS TODAY'S BEHAVIOUR, EXACTLY. Every app that does not carry this field runs the same
   *  ceremony it ran before the field existed: nothing extra is deployed, nothing extra is asked. That
   *  is deliberate and it is the safety property of the whole feature — this is the Home's onboarding
   *  path, shared by every member of the platform, so a new provisioning step has to be something an
   *  app OPTS INTO rather than something every app suddenly inherits. */
  new_member?: NewMemberOnboarding;
}

/**
 * First-connect provisioning a relying app declares for its members (the "what does a person need
 * before this app is usable" contract, stated by the app and honoured by the Home).
 *
 * The Home owns the ceremony; the app owns the requirement. A card room needs a player with a money
 * account and a name to show at the table, so it asks for both; a read-only directory app asks for
 * neither and is not touched. The app never gets to run the ceremony itself — declaring it here is
 * the only way to ask, which is what keeps "the app made me an account" impossible.
 *
 * EVERY field is optional and every omission means "don't". A `{}` here is the same as no field.
 */
export interface NewMemberOnboarding {
  /** Deploy the member's OWN personal treasury (`kind: 'person-treasury'`, custodied by their own
   *  credential, parented to their person SA) as part of first account creation, and record it so
   *  `/connect/related-orgs` discovery finds it.
   *
   *  NAMELESS BY DEFAULT, always — no label is claimed. A treasury's address is its canonical id
   *  (MAM-D4 name deferral), a label is globally unique per subregistry, and this runs for every new
   *  member of an app that asks for it: claiming here would mean racing thousands of people for the
   *  same obvious labels, and a failed claim must never cost someone the account itself. They can
   *  name it later from /treasuries.
   *
   *  The Home CREATES and CUSTODIES the account. Whether it also puts anything IN it is a separate,
   *  separately-gated question — see {@link MemberCurrency}. With no `currency` declared the account
   *  is opened empty, which is what this field alone has always meant. */
  personal_treasury?: boolean;
  /** Ask the member for their human name (what a person is CALLED — "Rich Pedersen"), stored as the
   *  first/last name on their private profile. Omit and they are never asked, which is today's
   *  behaviour: a phone or Google sign-up ends up with no name at all and renders as a truncated
   *  address everywhere, which is exactly the complaint this exists to fix.
   *
   *  This is NOT the `<label>.me` handle. The handle is a globally-unique on-chain name in the agent
   *  naming service and claiming one is a separate, deliberate act the member takes in their own
   *  home (see `requireNamedAgent` for the app-level version of THAT). Accounts made through this
   *  path stay nameless in the naming service on purpose.
   *
   *  'required' — the member must give a name before the connect continues.
   *  'optional' — the field is offered with a way past it. */
  collect_name?: 'required' | 'optional';
  /** THE APP'S OWN COIN — what its members hold, what they start with, and the authority its service
   *  agent needs to move it. Declaring this folds three acts into the ONE connect the member already
   *  makes. See {@link MemberCurrency}. Omit and none of them happen. */
  currency?: MemberCurrency;
}

/**
 * The currency a relying app's members transact in — the generic form of "this app has its own coin".
 *
 * WHY THIS IS A PLATFORM CAPABILITY AND NOT A CARD-ROOM FEATURE. An app with a service type and an
 * app-specific coin is a shape, not a special case: a card room's chips, a co-op's credits, a game's
 * tokens. Every one of them needs the same three things to exist before the app is usable — an
 * account that can hold the coin, some of the coin in it, and permission for the app's own agent to
 * move it — and every one of them was making the member run a SECOND ceremony to get the third.
 * Declaring the currency here means the member approves all three once, in the connect they were
 * already making, and the next app to want this writes a registry entry rather than a code path.
 *
 * WHAT IS DECLARED HERE AND WHAT IS DECLARED IN `paymentConfig`. The coin and the opening balance are
 * this app's currency and live here. The CAPS and the collecting account are a payment and live in
 * `paymentConfig`, which already carries exactly those and already has a ceremony that mints them —
 * so the spend grant is the existing payment mandate (`issuePaymentDelegation`), moved to the first
 * connect, not a second grant path beside it.
 *
 * THE ONE INVARIANT: `asset` here and `paymentConfig.asset` MUST be the same token. An app whose
 * registry entry disagrees with itself about which coin it deals in is a misconfiguration, and the
 * Home treats it as one — the whole capability switches OFF and says so, rather than opening an
 * account for one token and minting a mandate over another. (`memberCurrencyPlan` in
 * `lib/new-member.ts` is where that is enforced, and it is tested against the live registry.)
 *
 * EVERY FIELD BUT `asset` AND `name` IS OPTIONAL, and every omission means "don't".
 */
export interface MemberCurrency {
  /** The ERC-20 this app's members transact in. MUST equal `paymentConfig.asset` (see above); a
   *  disagreement, a missing `paymentConfig`, the zero address or anything that is not a 20-byte hex
   *  address all switch the capability off rather than guessing. */
  asset: `0x${string}`;
  /** What the member is told they have — "Sheqel". BRANDABLE, so it is config and never a literal in
   *  a component: the next app's coin is called something else and no code should have to change. */
  name: string;
  /** The plural, when it is not `name` + "s" ("Sheqels" is fine; "Pence" is not). */
  plural?: string;
  /** Atomic-unit decimals of `asset` — how `initial_amount` and the caps become the figures a person
   *  reads. Declared rather than read from the token because this is a CURATED registry and a display
   *  string should not depend on a network round trip that can fail mid-sign-up. */
  decimals: number;
  /** Atomic units placed in a member's account when it holds NONE of this coin. Omit for no seeding —
   *  the account is opened empty and the app funds it however it likes.
   *
   *  ONLY EVER PLAY MONEY. The Home can put coin in an account only by MINTING it, which is possible
   *  at all only for a token anyone may mint. So seeding requires `faucet: true` below AND the Home
   *  proving on chain that the token really is open-mint before it tries. A real asset fails both and
   *  the Home refuses loudly rather than half-doing it. */
  initial_amount?: string;
  /** THE APP SAYING, OUT LOUD AND IN A CURATED FILE, THAT THIS COIN IS PLAY MONEY — an ERC-20 with a
   *  permissionless `mint(address,uint256)`, deployed for a demo. It is a declaration of intent, not
   *  a proof: the Home also simulates the mint on chain and refuses if it reverts. Both must hold.
   *  Without this, `initial_amount` is ignored and the account is opened empty. */
  faucet?: boolean;
  /** Mint the `paymentConfig` mandate in THIS connect, so the app's service agent can move the
   *  member's coin without sending them through a second ceremony.
   *
   *  It rides the plain sign-in the member is already making, on the SAME credential and in the SAME
   *  signature batch as the site grant, and it moves no money — it is a ceiling, and the app spends
   *  against it later. The delegate is `paymentConfig.redeemer ?? payee`, the caps are
   *  `paymentConfig`'s, and all of it is disclosed at consent (`withCurrencyConsent`). Omit and the
   *  app keeps whatever payment ceremony it runs today. */
  spend_grant?: boolean;
}

/** Human-readable consent disclosure for a delegation template. The caveats themselves are
 *  contract-enforced (spec 230); this is the presentational can/cannot shown at consent. */
export interface DelegationTemplate {
  canDo: string[];
  /** Required, ≥1 — honest disclosure. <ConsentSheet> throws in dev if empty. */
  cannotDo: string[];
  /** Drives "Permission expires in N days" (omit → "ongoing until you revoke"). */
  expiryDays?: number;
}

/**
 * A relying app's OWN consent wording (per CLIENT, never per deployment).
 *
 * WHY THIS EXISTS. `delegationTemplates` and `copy` are shared by every app on this Home, and they are
 * written in the Home's vocabulary — funds, custody, recovery, the community. An app whose people never
 * meet any of that (a church host listing a group) reads those lines as alarms about things it cannot
 * even do. Rewording the shared lines would change every other app's sheet, so the app says it in its
 * own words HERE and the consent surfaces prefer it (`whitelabel/client-consent.ts`).
 *
 * PRESENTATION ONLY. The caveats are fixed by the template and enforced by contract (spec 230); nothing
 * here widens or narrows what the grant can do — it changes which sentences describe it. Every field is
 * optional and every omission means "the shared default", so a client without this renders as before.
 */
export interface ClientConsentCopy {
  /** Keyed by delegation template id (`site-login`, `org-create`, …). A template not listed keeps the
   *  shared disclosure. `canDo` REPLACES the composed list — including the lines the email / name /
   *  currency helpers add — so it must itself say everything the app receives (client-consent.test.ts
   *  pins that an email-claim client's lines mention the email). */
  templates?: Record<string, {
    canDo: string[];
    /** Replaces the shared "cannot" list. Ignored when `hideCannotDo` is set. */
    cannotDo?: string[];
    /** Drop the "This app cannot" block. For an app whose people never hold funds, keys or recovery
     *  through it, a list of those things is noise that reads as a warning. */
    hideCannotDo?: boolean;
  }>;
  /** What "Signed in as" names. `'email'` — the member's own verified email off their vault profile
   *  (best-effort; falls back to the name, then the short address). Absent — name, then short address. */
  signedInAs?: 'email';
  /** The account-switch button on the recognized consent screen, in the app's own words (same action:
   *  clear the session, back to the sign-in door). Absent → "Not <you>? Use a different custodian". */
  switchAccountLabel?: string;
  /** The org-create sheet's own prose (OrgConsent), for an app whose org is something else to its
   *  people (Gather27: a church's listing). `{app}` / `{org}` are interpolated (`fmt`). Each absent key
   *  keeps the shared sentence; the select-existing wording is never replaced. */
  orgCreate?: {
    /** The explainer paragraph above the sheet for a NEW org. */
    explainer?: string;
    /** The "You can disconnect … from your … home" line. */
    disconnect?: string;
    /** The "is ready" receipt body for a NEW org. */
    receipt?: string;
  };
  /** Hide the hard-coded "<Home> · a Home on the Agentic Primitives substrate" line in the sign-in
   *  card's footer. The credit and links are env-driven (NEXT_PUBLIC_FOOTER_*) and are NOT touched. */
  hideSubstrate?: boolean;
  /** Overrides of shared copy keys for this client's flow (e.g. `portalStepBusy`). */
  copy?: Partial<WhiteLabelCopy>;
  /** Exact-string replacements for ceremony progress labels and hints (`CeremonyProgress`), e.g. a
   *  shared "Confirming it on the chain…" an app's people should never see. Unlisted text is unchanged. */
  progressText?: Record<string, string>;
  /** Never show the person an address, a handle or a `.impact` name on this client's screens: "Signed
   *  in as" names only the verified email (or just says "Signed in"), progress lines that would name a
   *  handle are replaced with a plain one, and org handles are humanized. For an app whose people only
   *  ever know themselves by their email (Gather27). */
  hideIdentifiers?: boolean;
}

/**
 * A relying app's OWN look for the sign-in window it opens on this Home (per CLIENT, never per
 * deployment) — so a person who clicked "Sign in" on the app does not land on a page that looks
 * like somebody else's.
 *
 * PRESENTATION ONLY, and scoped: the vars are set on a wrapper around that window's onboarding
 * screens (portal Gate → `ClientThemeScope`), so they override the Home's own CSS variables
 * (globals.css `:root`) for those screens and nothing else. The `--theme-*` vars feed the few shape
 * rules under `.client-theme` in globals.css (pill buttons, heading face, card radius). A client
 * without this renders exactly as before.
 */
export interface ClientTheme {
  /** A Google Fonts stylesheet URL, loaded only while the theme is active. */
  fontHref?: string;
  /** CSS custom properties (each key starts with `--`) set on the scope. */
  vars: Record<string, string>;
  /** An extra class on the scope, for a client that needs a hook of its own. */
  className?: string;
}

/** An agent kind the Portal lets the user manage. Person is live; others preview. */
export interface ManageableAgent {
  id: 'person' | 'organization' | 'treasury' | 'data-source';
  label: string;
  blurb: string;
  status: 'live' | 'soon';
  /** The stewardship verb for this kind ("oversee" | "manage" | "protect"). */
  verb?: string;
}

/** Tokenized copy for the Experience Layer. {name} = the user's name; {app} = relying app. */
export interface WhiteLabelCopy {
  // Arrival into the Home — belonging + ownership, not a login page.
  arrivalTitle: string;
  /** The line under "Continue to <app>" in a relying app's sign-in window. */
  enrollSub: string;
  arrivalBody: string;
  // Onboarding overview (lists the value steps up front).
  overviewTitle: string;
  // Value step ① — your own Portal (deploy the person SA).
  portalStepTitle: string;
  portalStepValue: string;
  // The CREATE-passkey CTA (gesture 1 — mint the key; passkey path only).
  portalStepCreateCta: string;
  // The APPROVE-setup CTA (gesture 2 — use the key just made to deploy + claim; passkey path only).
  portalStepCta: string;
  portalStepBusy: string;
  portalStepReceipt: string;
  // Receipt shown right after the passkey is CREATED, before the approve step (passkey path only).
  portalKeyCreatedReceiptTitle: string;
  portalKeyCreatedReceiptBody: string;
  // Value step ② — your place in the community (claim the name; batched with ①).
  communityStepTitle: string;
  communityStepValue: string;
  communityStepReceipt: string;
  // Value step ③ — access for the relying app (scoped delegation).
  authorizeStepTitle: string;
  authorizeStepValue: string;
  authorizeStepCta: string;
  authorizeStepBusy: string;
  authorizeStepReceipt: string;
  // Portal (signed-in).
  portalTitle: string;
  portalWelcome: string;
  portalYouLabel: string;
  portalManageHeading: string;
}

export interface WhiteLabelConfig {
  /** Stable id of this white-label (e.g. 'faith-impact'). */
  id: string;
  brand: {
    /** Short platform/community brand, e.g. "Impact". */
    name: string;
    /** Community noun, e.g. "Impact community". */
    community: string;
    tagline: string;
  };
  /** Deployment domains — sourced from lib/domain.ts (the ADR-0021 single source). */
  domains: { connect: string; a2a: string; nameParent: string };
  /**
   * The Home's footer: where this Home's substrate, its ontologies and its maker live. Rendered under every
   * portal section and under the sign-in card; a deployment sets `NEXT_PUBLIC_FOOTER_LINKS` (JSON array of
   * `{ label, href }`) to replace the defaults. Cross-links, never a menu: nothing here is a route of the Home.
   */
  footer: {
    /** The one-line credit before the links, e.g. "Built on Agentic Primitives". */
    credit: string;
    links: ReadonlyArray<{ label: string; href: string; /** rel for an outbound link; defaults to noopener. */ rel?: string }>;
  };
  onboarding: {
    credentialMethods: Array<'passkey' | 'wallet' | 'google' | 'youversion' | 'email' | 'phone'>;
  };
  /** Which Portal surfaces are enabled for this deployment. */
  services: { devices: boolean; connectedApps: boolean };
  /** The "agents you manage" grid in the Portal. */
  manageableAgents: ManageableAgent[];
  /** Relying apps (the configured OIDC client registry). */
  relyingApps: RelyingApp[];
  /** Consent disclosure per delegation template (the human-readable can/cannot at consent). */
  delegationTemplates: Record<string, DelegationTemplate>;
  copy: WhiteLabelCopy;
}
