// Build the broker `Env` (the shape the ported Pages-Function bodies expect)
// from Vercel's `process.env` + the Vercel KV adapter. This is the ONLY runtime
// seam that changes between the Cloudflare Pages broker and the Vercel one — the
// endpoint logic in `server/**` is ported verbatim (spec 232 §3).
//
// `PROXY_SHARED_SECRET` is intentionally NOT set: on Vercel the route handler
// sees the real Host, so `resolveOrigin` degrades to `new URL(request.url).origin`
// — the per-person OP issuer is correct natively (no proxy hop, no secret).
import type { Env } from '../../server/_lib/server-broker';
import { DEMO_EDGE_ORIGIN_DEFAULT } from '../../src/lib/domain';
import { kv } from './kv';

// Trim surrounding whitespace from env values — pasted dashboard values often carry a trailing
// space/newline, and e.g. a GOOGLE_REDIRECT_URI with a trailing space no longer EXACTLY matches
// the registered Google redirect URI (Google rejects it as invalid_request / secure-response-handling).
const t = (v: string | undefined): string | undefined => (v == null ? v : v.trim());

export function makeEnv(): Env {
  // Don't throw here — only routes that actually mint/verify tokens need the key,
  // and `getServer()` throws on an empty key on demand (matching the original
  // Cloudflare broker). This lets key-free routes (e.g. openid-configuration
  // discovery) work without the signing secret.
  return {
    BROKER_PRIVATE_JWK: process.env.BROKER_PRIVATE_JWK ?? '',
    BROKER_KID: t(process.env.BROKER_KID),
    AUTH_CODES: kv,
    RPC_URL: t(process.env.RPC_URL),
    REDIRECT_URI_ALLOWLIST: t(process.env.REDIRECT_URI_ALLOWLIST),
    GOOGLE_CLIENT_ID: t(process.env.GOOGLE_CLIENT_ID),
    GOOGLE_CLIENT_SECRET: t(process.env.GOOGLE_CLIENT_SECRET),
    GOOGLE_REDIRECT_URI: t(process.env.GOOGLE_REDIRECT_URI),
    YOUVERSION_CLIENT_ID: t(process.env.YOUVERSION_CLIENT_ID),
    YOUVERSION_REDIRECT_URI: t(process.env.YOUVERSION_REDIRECT_URI),
    // Google × KMS custody (spec 235): the callback asks demo-a2a to derive the member's
    // KMS-custodied SA. Without these the callback degrades to login-grade (no custody).
    A2A_CUSTODY_URL: t(process.env.A2A_CUSTODY_URL),
    A2A_CUSTODY_BRIDGE_SECRET: t(process.env.A2A_CUSTODY_BRIDGE_SECRET),
    // Vault message-body path (spec 317). The edge defaults to the prod origin (mirrors next.config), so it
    // needs no Vercel var; `''` disables it (edge-less dev). The server enable-flag SA falls back to the
    // public var, so setting ONLY `NEXT_PUBLIC_DELIVERY_SERVICE_SA` turns on BOTH the client onboarding grant
    // and the server body-store — one variable, no drift between the two.
    DEMO_EDGE_URL: t(process.env.DEMO_EDGE_URL) ?? DEMO_EDGE_ORIGIN_DEFAULT,
    A2A_VAULT_URL: t(process.env.A2A_VAULT_URL),
    DELIVERY_SERVICE_SA: t(process.env.DELIVERY_SERVICE_SA) ?? t(process.env.NEXT_PUBLIC_DELIVERY_SERVICE_SA),
    // Email auth + invites (SendGrid). Unset ⇒ the sender logs instead of sending (deploy-safe).
    SENDGRID_API_KEY: t(process.env.SENDGRID_API_KEY),
    EMAIL_FROM: t(process.env.EMAIL_FROM),
    // Phone auth (Twilio Verify). Unset ⇒ a self-generated dev OTP is logged instead (deploy-safe).
    TWILIO_API_KEY: t(process.env.TWILIO_API_KEY),
    TWILIO_API_KEY_SECRET: t(process.env.TWILIO_API_KEY_SECRET),
    TWILIO_VERIFY_SERVICE_SID: t(process.env.TWILIO_VERIFY_SERVICE_SID),
    // Twilio Programmable Messaging (texts our own OTP — no Verify upgrade). Account SID + a From number.
    TWILIO_ACCOUNT_SID: t(process.env.TWILIO_ACCOUNT_SID),
    TWILIO_FROM_NUMBER: t(process.env.TWILIO_FROM_NUMBER),
    // Testing: echo the dev OTP in the response when a provider is UNCONFIGURED (a real SendGrid/Twilio
    // NEVER echoes). FAIL-CLOSED DEFAULT (audit 2026-07-13 CRIT-1): defaults OFF so a missing/misconfigured
    // provider is a fail-closed OUTAGE (no code delivered), NOT an OTP disclosure that mints a session/custody.
    // A developer testing with no provider must OPT IN explicitly via DEV_OTP_ECHO=true (never in production).
    DEV_OTP_ECHO: t(process.env.DEV_OTP_ECHO) ?? 'false',
    DEMO_SSO_AUD: t(process.env.DEMO_SSO_AUD),
    // How long a minted id_token lives. Unset → 7 days (see server/_lib/session-ttl.ts). Set it
    // LOWER in a deployment with real users: the token is a bearer credential with no revocation.
    ID_TOKEN_TTL_SECONDS: t(process.env.ID_TOKEN_TTL_SECONDS),
    // Shared demo people (Nathan, David…) custodied HERE so every app can sign them in and their
    // own portal can run ceremonies without a wallet. Demo keys only — never a real person's.
    DEMO_PERSONA_KEYS: t(process.env.DEMO_PERSONA_KEYS),
    DEMO_SIGNER_SECRET: t(process.env.DEMO_SIGNER_SECRET),
    ALLOWED_ISSUER_HOSTS: t(process.env.ALLOWED_ISSUER_HOSTS),
    HOME_ADMINS: t(process.env.HOME_ADMINS),
    HOME_OPERATOR_ORG: t(process.env.HOME_OPERATOR_ORG),
    CONTACT_DIRECTORY_KEY: t(process.env.CONTACT_DIRECTORY_KEY),
    AZURE_TENANT_ID: t(process.env.AZURE_TENANT_ID),
    AZURE_CLIENT_ID: t(process.env.AZURE_CLIENT_ID),
    AZURE_CLIENT_SECRET: t(process.env.AZURE_CLIENT_SECRET),
    AZURE_SUBSCRIPTION_ID: t(process.env.AZURE_SUBSCRIPTION_ID),
    AZURE_BUDGET_NAME: t(process.env.AZURE_BUDGET_NAME),
    AZURE_RG_LABELS: t(process.env.AZURE_RG_LABELS),
  };
}
