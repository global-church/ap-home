#!/usr/bin/env node
// check:home-kv-allowlist (spec 323 W5) — the KV-creep gate.
//
// After spec 323, demo-sso-next's Cloudflare KV may hold ONLY (C) rebuildable caches/projections of
// data whose canonical home is the vault/DO/KB/chain, and (E) ephemeral ceremony state. NO durable
// capability, private graph, or delegation WIRE may live in KV — those moved to the per-principal
// InteractionsDO / owner vault so a second Home reaches them (docs/architecture/portable-home.md).
//
// This gate extracts every KV key prefix the app touches (AUTH_CODES.put/get/delete + `*Key`/KEY
// helper definitions) and fails on any prefix not in the classified ALLOWLIST below. Adding a new
// durable KV namespace forces a reviewer to either (a) classify it C/E with a rationale here, or
// (b) — if it's real capability/graph/wire state — put it in the vault/DO instead (the whole point).

import { readFileSync } from 'node:fs';
import { execSync } from 'node:child_process';

const ROOT = 'apps/home';

// prefix → { class: 'cache' | 'ephemeral', why }
const ALLOWLIST = {
  // ── Ephemeral ceremony state (short-TTL, per-flow; each Home runs its own) ──
  'nonce': { class: 'ephemeral', why: 'SIWE/challenge nonces' },
  'pkchallenge': { class: 'ephemeral', why: 'passkey WebAuthn challenge' },
  'code': { class: 'ephemeral', why: 'OAuth authorization code (single-use)' },
  'oidc': { class: 'ephemeral', why: 'OIDC authorize state' },
  'oidc-deleg': { class: 'ephemeral', why: 'transient OIDC delegation-request state' },
  'oidc-grant': { class: 'ephemeral', why: 'transient OAuth grant bundle handle' },
  // The person's own self-grant (delegator = delegate = them), verified on chain before storage and
  // stored with a TTL that expires with its own timestamp caveat. Rebuildable by definition: losing it
  // costs one signature, which is the prompt this exists to avoid — a rebuild, never a bereavement
  // (ADR-0055). It is NOT in related-orgs on purpose (spec 345 §0: a person is not an org they steward).
  'self-grant': { class: 'ephemeral', why: 'person self-grant, chain-verified, expires with its caveat' },
  'emailotp': { class: 'ephemeral', why: 'email OTP code' },
  'phoneverify': { class: 'ephemeral', why: 'phone OTP code' },
  'linkreq': { class: 'ephemeral', why: 'credential-link request' },
  'link-failed': { class: 'ephemeral', why: 'link-attempt failure marker' },
  'rag-nonce': { class: 'ephemeral', why: 'related-agents signed-write one-shot nonce' },
  'fedcm-grant-nonce': { class: 'ephemeral', why: 'FedCM grant nonce' },
  'wsinvite': { class: 'ephemeral', why: 'P4 workspace-member invite stash: custodian-signed grant in transit between the invite and join ceremonies; single-use (deleted on claim), 7-day TTL; carries no authority of its own' },
  // ── Rebuildable caches / projections (canonical home is the vault/DO/KB/chain) ──
  // HOME-PORT-2 (2026-07-12): this table classifies by PREFIX NAME; a 'cache' rationale is a REVIEWER
  // ASSERTION, not a programmatically-verified rebuild path. The three wire-bearing prefixes below carry a
  // KNOWN, TRACKED gap (HOME-PORT-1) — read their 'why' literally, do not treat them as verified-portable.
  'contact': { class: 'cache', why: 'the operator copy of a person’s verified contact email (contact-directory.ts, 2026-10-21): AES-256-GCM under CONTACT_DIRECTORY_KEY, readable only through the Admin lookup, which records each read on the record. The record is the person’s own vault profile (impact-profile contact.email, seeded at sign-in); this copy is rewritten at their next sign-in if lost.' },
  'contact-views': { class: 'cache', why: 'the record of who opened Admin’s Organizations list (contact-directory.ts recordContactView, 2026-10-22): admin address, time, which app, how many emails shown; the last 500. Audit trail, not a record of anything else; losing it loses only the history of views.' },
  'co-manager': { class: 'ephemeral', why: 'a pending offer to co-manage an organization (co-manager.ts, 2026-10-23): the org-signed stewardship grant waits here until the person accepts as themselves, 30-day TTL; at acceptance the grant moves to the person’s related link (where every stewardship wire is cached and re-verified on-chain) and is dropped from the offer.' },
  'co-manager-idx': { class: 'cache', why: 'which people an organization has offered co-management to (co-manager.ts): addresses only, rebuildable, no wire.' },
  'orgcontactotp': { class: 'ephemeral', why: 'the code that confirms a new contact email for an organization (org-contact.ts, 2026-10-22): keyed by org and email hash, 10-minute TTL, single use.' },
  'related': { class: 'cache', why: 'relationship link. The STEWARDSHIP wire self-heals from the person vault relationships.data (spec 323 W1); but the member→org membershipDelegation stored here is NOT mirrored to the vault — that wire is Home-KV-only (HOME-PORT-1, OPEN).' },
  'related-idx': { class: 'cache', why: 'index of the relationships.data projection (spec 323 W1)' },
  'related-miss': { class: 'cache', why: 'five-minute NEGATIVE cache (expirationTtl 300): this person has no relationships.data entry for this org — skips the per-request vault read in stewardWireFor; consulted only after the related: link, rebuilt from the vault on expiry' },
  // Spec 397 W4 — the person-level app wires (the Home MCP's ask-as-me) a person authorized, so Connected assistants can
  // LIST and REVOKE them. The wire itself is signed by the person, held by the app's Worker and revocable ON CHAIN; this
  // is the index of which apps were granted. KNOWN GAP (HOME-PORT-2, OPEN): the honest home is the person's vault
  // (spec 323 — a second Home cannot list them from here); until it moves, a lost index costs the listing and the
  // one-click revoke, never the authority (revocation by owner works from the wire alone).
  'app-grants': { class: 'cache', why: 'index of person-level app wires (spec 397 W4) — rebuild source: the person re-authorizing; move to the vault (HOME-PORT-2)' },
  'delegated-idx': { class: 'cache', why: 'inbound member-grant WIRE cache. KNOWN GAP (HOME-PORT-1, OPEN): the claimed rebuild source is not real yet — DirectoryListingV1 carries no delegation wire and no members grants.list writer exists, so a second Home cannot reconstruct these authority wires. NOT verified-portable; tracked in findings.yaml HOME-PORT-1.' },
  'skills': { class: 'cache', why: 'projection of the person vault skills.data (spec 323 W2)' },
  'library': { class: 'cache', why: 'projection of the principal vault library.index (Content Artifacts) — rebuildable (spec 335)' },
  'home-control': { class: 'cache', why: 'projection of the person vault control-events.data (spec 323 W2.3)' },
  'home-manifest': { class: 'cache', why: 'public /.well-known serve cache of the vault home.manifest master (spec 323 W2.2)' },
  'inbox-data': { class: 'cache', why: 'intercepted docKey — makeInboxKv routes it to the InteractionsDO; never written to KV (spec 323 W3f)' },
  'inbox-audit': { class: 'cache', why: 'projection of the D1 audit log (spec 291)' },
  'namecache': { class: 'cache', why: 'reverse-resolve name cache (chain is canonical, ADR-0013)' },
  'org-teams': { class: 'cache', why: 'spec 428 — an org\'s teams + each team→org content grant, for the org stewards\' related-orgs rows. Rebuildable: re-run backfill-428-team-read.mts (re-mints + approves). Discovery only (ADR-0056).' },
  'org-workspace': { class: 'cache', why: 'spec 424 — an org\'s governed workspace + its ws→org content grant, for members\' related-orgs rows. Rebuildable: the grant\'s original is on the workspace\'s own `workspace.governor` record (backfill-424-governed-workspace.mts). Discovery only (ADR-0056).' },
  'org-localname': { class: 'cache', why: 'an agent\'s owner-chosen LOCAL name for the trust graph when it has no public name. Rebuildable from the steward\'s own records (backfill-local-names.mts); a public name always wins.' },
  // ── Member-registered OIDC clients (spec 230 §6 self-service half) ──
  // HONEST CLASSIFICATION: these are NOT caches and there is no vault original to rebuild from —
  // the KV record IS the registration. Marked here rather than dressed up as a projection, because
  // the entry above (`delegated-idx`) sets the precedent that an unverified rebuild path gets said
  // out loud instead of asserted.
  //
  // WHY IT CANNOT SIMPLY MOVE TO THE OWNER'S VAULT (yet): `/oidc/authorize-grant` must resolve a
  // `client_id` for an ANONYMOUS visitor — someone arriving at the Home before any session for that
  // client exists. A vault read needs the owner's delegation, which is precisely what is absent at
  // that moment. So the gate needs a Home-readable copy.
  //
  // THE PORTABLE SHAPE, tracked as follow-up: authoritative record in the registering member's vault,
  // KV as its projection — the `related:`/`skills:` pattern — so a wipe rebuilds from vaults and a
  // second Home reconstructs the registry. Until that exists, a wipe loses member registrations.
  'oidc-app': { class: 'cache', why: 'member-registered OIDC client. KNOWN GAP: NOT rebuildable — no vault original exists yet; the portable shape (vault-authoritative + KV projection) is tracked follow-up. Home-readable because the OIDC gate resolves client_id for an anonymous caller.' },
  'oidc-app-owner': { class: 'cache', why: 'per-owner index of the above. Same KNOWN GAP — rebuildable only once the vault-authoritative record exists.' },
  'oidc-app-origin': { class: 'cache', why: 'origin → client_id index for the CORS/redirect gate; derivable from the oidc-app records, so rebuildable once those are.' },
};

// Files that touch AUTH_CODES — scan these for key prefixes.
const files = execSync(
  `grep -rl "AUTH_CODES" ${ROOT}/server ${ROOT}/src --include='*.ts' --include='*.tsx'`,
  { encoding: 'utf8' },
).trim().split('\n').filter(Boolean);

// Two precise extractors: inline AUTH_CODES.(put|get|delete)(`prefix:  and  `*Key`/KEY helper defs.
const INLINE = /AUTH_CODES\.(?:put|get|delete)\(\s*`([a-z][a-z0-9-]+):/g;
const KEYDEF = /(?:const\s+\w*(?:KEY|Key|key)\w*|=>)\s*=?\s*`([a-z][a-z0-9-]+):/g;

const used = new Map(); // prefix → Set(file)
for (const f of files) {
  const src = readFileSync(f, 'utf8');
  for (const re of [INLINE, KEYDEF]) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(src))) {
      const p = m[1];
      if (!used.has(p)) used.set(p, new Set());
      used.get(p).add(f.replace(`${ROOT}/`, ''));
    }
  }
}

const unknown = [...used.keys()].filter((p) => !ALLOWLIST[p]).sort();
if (unknown.length > 0) {
  console.error('✗ check:home-kv-allowlist — unclassified durable KV namespace(s):\n');
  for (const p of unknown) {
    console.error(`  ${p}:  (in ${[...used.get(p)].join(', ')})`);
  }
  console.error(`
A new KV key prefix appeared. demo-sso-next KV is caches + ephemeral ONLY (spec 323).
If this is real capability/graph/wire state, put it in the owner's vault/InteractionsDO instead
(docs/architecture/portable-home.md). If it is genuinely a rebuildable cache or ephemeral ceremony
state, add it to ALLOWLIST in scripts/check-home-kv-allowlist.mjs with a one-line rationale.`);
  process.exit(1);
}

console.log(`✓ check:home-kv-allowlist — ${used.size} KV namespace(s), all classified cache/ephemeral:`);
for (const p of [...used.keys()].sort()) console.log(`  ${p.padEnd(20)} ${ALLOWLIST[p].class}`);
