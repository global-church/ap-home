// Shared helper for the server-side (Pages Function) Connect broker. Files/dirs
// starting with `_` are NOT routed by Pages, so this is a plain module.
//
// The broker SIGNING KEY lives server-side here (an env secret), never in the
// browser — that is the whole point of the broker being a server (ADR-0014).
// The directory + issuance/verification logic is the SAME broker-core the
// in-browser demo uses; only the key source + the transport differ.

import { publishJwks } from '@agenticprimitives/connect';
import { signerFromPrivateJwk } from '../../src/lib/broker-core';
export { resolveOrigin, ownIssuer } from './origin';
import { buildRealDirectory } from '../../src/lib/real-directory';
import { createKvIndexer } from '../../src/lib/kv-indexer';
import { isAllowedClientOrigin } from '../../src/lib/oidc-clients';

/** Minimal Cloudflare KV surface (avoids a @cloudflare/workers-types dep). */
export interface KVNamespace {
  get(key: string): Promise<string | null>;
  put(key: string, value: string, opts?: { expirationTtl?: number }): Promise<void>;
  delete(key: string): Promise<void>;
  /** Cloudflare-KV-shaped prefix listing. The Vercel adapter backs it with Upstash SCAN (app/_lib/kv.ts).
   *  Used to enumerate a custodian's `related:<sa>:*` records (demo-selves). Cursor-paged; a batch may be
   *  partial or empty, so callers loop until `list_complete`. */
  list(opts?: { prefix?: string; cursor?: string; limit?: number }): Promise<{ keys: { name: string }[]; list_complete: boolean; cursor?: string }>;
}

export interface Env {
  /** ES256 (ECDSA P-256) PRIVATE JWK (JSON string). Secret: `wrangler pages secret put BROKER_PRIVATE_JWK`. */
  BROKER_PRIVATE_JWK: string;
  /** Key id published in the JWKS. */
  BROKER_KID?: string;
  /** Single-use auth-code store (CN-9) + the persistent login-facet index
   *  (`facet:` keys; spec 227 §5). `[[kv_namespaces]]` binding in wrangler.toml. */
  AUTH_CODES: KVNamespace;
  /** Base Sepolia RPC for on-chain resolution. Defaults to the public endpoint. */
  RPC_URL?: string;
  /** Comma-separated exact-match relying-site redirect URIs (CN-1). */
  REDIRECT_URI_ALLOWLIST?: string;
  /** Shared secret with the `*.impact-agent.io` subdomain-router Worker
   *  (spec 231). When a request carries `X-Proxy-Secret` matching this AND an
   *  `X-Forwarded-Host`, the broker derives its issuer origin from that host —
   *  so the per-person OP `iss` stays `https://<handle>.impact-agent.io` even
   *  though the Worker proxies to this pages.dev origin. The secret gate
   *  prevents direct-to-pages.dev issuer spoofing. See functions/_lib/origin.ts. */
  PROXY_SHARED_SECRET?: string;

  // ─── Google OIDC (real). See OIDC-SETUP.md. ────────────────────────
  /** Google OAuth 2.0 Client ID (public-ish; set as a Pages env var/secret). */
  GOOGLE_CLIENT_ID?: string;
  /** Google OAuth 2.0 Client SECRET — server-side only; `wrangler pages secret put`. */
  GOOGLE_CLIENT_SECRET?: string;
  /** Must EXACTLY match the redirect URI registered in Google Cloud Console,
   *  e.g. https://<your-connect-origin>/oidc/google/callback */
  GOOGLE_REDIRECT_URI?: string;

  // ─── YouVersion Platform OIDC (real). developers.youversion.com/sign-in-apis ──
  /** YouVersion App Key — the PUBLIC PKCE client_id (set as a Pages env var). There is NO client
   *  secret: YouVersion is a public PKCE client, so only the App Key + redirect URI are needed. */
  YOUVERSION_CLIENT_ID?: string;
  /** Must EXACTLY match the callback URL registered in the YouVersion Platform Portal,
   *  e.g. https://www.impact-agent.me/oidc/youversion/callback */
  YOUVERSION_REDIRECT_URI?: string;

  // ─── Google × KMS custody (spec 235) ───────────────────────────────
  /** demo-a2a base URL for the server-to-server custody RESOLVE call (e.g.
   *  `https://<a2a-worker>`). The broker can't hold the master, so during the
   *  OIDC callback it asks demo-a2a to derive the member's KMS-custodied SA.
   *  When unset, Google stays login-grade only (no custody path). */
  A2A_CUSTODY_URL?: string;
  /** Shared secret for the resolve call — must match demo-a2a's
   *  `A2A_CUSTODY_BRIDGE_SECRET`. */
  A2A_CUSTODY_BRIDGE_SECRET?: string;
  /** The Personal-Home `aud` for which Google sign-in mints a CUSTODY-grade,
   *  KMS-custodied session. Defaults to `'demo-sso'`. Relying-app auds stay
   *  login-grade (they onboard members through the Personal Home). */
  DEMO_SSO_AUD?: string;
  /** How long a minted id_token stays valid, in seconds. Unset → SESSION_TTL_DEFAULT (7 days).
   *  It is a BEARER credential with no revocation path, so the value is a deliberate trade between
   *  how often a person re-authenticates and how long a leaked token keeps working. */
  ID_TOKEN_TTL_SECONDS?: string;

  // ─── Vault message-body path (spec 317) ───────────────────────────
  /** The Agentic Edge origin (assertion signer) the server-side vault body-store routes `/mcp/vault/*`
   *  through. Defaults to the prod edge (`DEMO_EDGE_ORIGIN_DEFAULT`, mirroring `next.config`) — you do NOT
   *  set it on Vercel; override only for an edge-less local dev. */
  DEMO_EDGE_URL?: string;
  /** Direct demo-a2a origin serving `/mcp/vault/*` — used ONLY for an edge-less deploy (`DEMO_EDGE_URL=''`). */
  A2A_VAULT_URL?: string;
  /** The provisioned delivery-service SA (spec 317 §3.4). Its PRESENCE is the vault-body ENABLE flag. Derived
   *  from `NEXT_PUBLIC_DELIVERY_SERVICE_SA` when the server-only var is unset, so ONE Vercel var enables both
   *  the client onboarding grant AND the server body-store. */
  DELIVERY_SERVICE_SA?: string;

  // ─── Email auth + invites (SendGrid) ───────────────────────────────
  /** SendGrid API key — its presence flips the email sender from log-only to live. Secret. */
  SENDGRID_API_KEY?: string;
  /** Verified SendGrid sender address (e.g. no-reply@impact-agent.me) — required to actually send. */
  EMAIL_FROM?: string;

  // ─── Phone auth (Twilio Verify) ────────────────────────────────────
  /** Twilio API key SID (SK…) + secret — presence flips SMS verification from dev-OTP to Twilio Verify. */
  TWILIO_API_KEY?: string;
  TWILIO_API_KEY_SECRET?: string;
  /** Twilio Verify Service SID (VA…) — the configured Verify service. */
  TWILIO_VERIFY_SERVICE_SID?: string;
  /** Twilio Account SID (AC…) + a From (a +1… number or MG… Messaging Service SID) — enables Programmable
   *  Messaging delivery of our own dev OTP (trial-friendly, no Verify upgrade). */
  TWILIO_ACCOUNT_SID?: string;
  TWILIO_FROM_NUMBER?: string;
  /** Testing convenience: when `'true'` AND the provider is UNCONFIGURED, the email/phone start routes
   *  echo the self-generated dev OTP in the response (so a tester needn't read server logs). OFF by
   *  default — a CONFIGURED provider (SendGrid/Twilio) NEVER echoes. Never enable on a real deployment. */
  DEV_OTP_ECHO?: string;

  // ─── Demo accounts (shared demo people, custodied here) ────────────
  /** JSON registry of the seeded DEMO personas this Home custodies: either the apps' seed shape
   *  `{handle: {sa, eoaPrivateKey, name, blurb}}` or a flat `{"0x<sa>": "0x<privateKey>"}` map.
   *  Its presence enables /connect/demo-personas, /connect/demo-signin and /connect/persona-sign —
   *  demo keys ONLY (see server/_lib/demo-custody.ts). Unset ⇒ all three are inert. */
  DEMO_PERSONA_KEYS?: string;
  /** Shared secret a demo APP presents to `PUT /connect/demo-sign` when it runs a ceremony on a demo
   *  person's behalf (org deploy, vault-key, admissions) — there is no person session in those flows.
   *  Unset ⇒ that route is off (the session-gated /connect/persona-sign is unaffected). */
  DEMO_SIGNER_SECRET?: string;

  /** SEC-006: comma-separated allowlist of inbound `Host` headers the broker will
   *  mint id_tokens for. Wildcards like `*.impact-agent.me` match exactly one label.
   *  When unset, defaults to the production patterns (impact-agent.me + its subdomains
   *  + localhost). A request with a foreign Host is rejected — the broker will never
   *  sign `iss=<attacker-host>`. */
  ALLOWED_ISSUER_HOSTS?: string;
  /** The Admin tab (2026-10-09): comma list of person addresses allowed to open it. Unset/empty = nobody. */
  HOME_ADMINS?: string;
  /** The operator organization (2026-10-23): admins are its stewards, and its vault holds the contact directory.
   *  Set, it replaces HOME_ADMINS and the encrypted KV directory (server/_lib/operator-directory.ts). */
  HOME_OPERATOR_ORG?: string;
  /** The operator contact directory's AES-256 key, base64 (32 bytes) — contact-directory.ts. Unset = no copies kept. */
  CONTACT_DIRECTORY_KEY?: string;
  /** Azure spending on the Admin tab: a read-only (Cost Management Reader) service principal on one subscription. */
  AZURE_TENANT_ID?: string;
  AZURE_CLIENT_ID?: string;
  AZURE_CLIENT_SECRET?: string;
  AZURE_SUBSCRIPTION_ID?: string;
  /** Which subscription budget to show (default: the first monthly one). */
  AZURE_BUDGET_NAME?: string;
  /** Friendly resource-group names: "rg-a=Chain,rg-b=Key service". */
  AZURE_RG_LABELS?: string;
}

/** Pages Function context (the subset these handlers use). */
export interface FnContext {
  request: Request;
  env: Env;
}

export async function getServer(env: Env) {
  if (!env.BROKER_PRIVATE_JWK) {
    throw new Error('BROKER_PRIVATE_JWK is not set. Generate one (see CLAUDE.md) and `wrangler pages secret put BROKER_PRIVATE_JWK`.');
  }
  const signer = await signerFromPrivateJwk(JSON.parse(env.BROKER_PRIVATE_JWK), env.BROKER_KID ?? 'broker-1');
  // Real Base Sepolia resolution (spec 227 §5): live naming + on-chain custody +
  // a persistent KV login-facet index. Replaces the in-memory demo directory.
  const directory = buildRealDirectory({ rpcUrl: env.RPC_URL, indexer: createKvIndexer(env.AUTH_CODES) });
  const jwks = await publishJwks([signer]);
  return { signer, directory, jwks };
}

export function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
}

/** CORS headers for the cross-origin OIDC endpoints (/token, /jwks) — reflects the request
 *  Origin ONLY if it's a registered client origin (spec 230 §8.10; not a broad `*`).
 *
 *  `alsoAllowed` admits an origin the CALLER already resolved — used by the endpoints that
 *  consult the member-registered client registry (`server/_lib/oidc-registry.ts`), which is a KV
 *  read and therefore async. Passing the verdict in keeps this helper synchronous for its 200-odd
 *  existing call sites while letting the OIDC endpoints answer for self-registered apps too. It
 *  defaults to `false`, so a caller that does not opt in behaves exactly as before. */
export function corsHeaders(request: Request, alsoAllowed = false): Record<string, string> {
  const origin = request.headers.get('Origin') ?? '';
  if (!origin || !(isAllowedClientOrigin(origin) || alsoAllowed)) return {};
  return {
    'access-control-allow-origin': origin,
    'access-control-allow-methods': 'POST, GET, OPTIONS',
    'access-control-allow-headers': 'content-type',
    'access-control-max-age': '600',
    vary: 'Origin',
  };
}

/** json() + CORS for a registered client origin. See `corsHeaders` for `alsoAllowed`. */
export function jsonCors(body: unknown, request: Request, status = 200, alsoAllowed = false): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', ...corsHeaders(request, alsoAllowed) },
  });
}

/** CORS preflight (204). See `corsHeaders` for `alsoAllowed`. */
export function preflight(request: Request, alsoAllowed = false): Response {
  return new Response(null, { status: 204, headers: corsHeaders(request, alsoAllowed) });
}
