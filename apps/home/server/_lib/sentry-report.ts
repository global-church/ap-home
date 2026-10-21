// SENTRY REPORTING (GC, 2026-10-21) — one error event to Sentry over its envelope endpoint, no SDK.
//
// WHY. A host saw a provider's raw "daily sending quota" error before anyone on the team knew (2026-10-20).
// Paul and Clayton want failures like that reported to Sentry so we see the next one first.
//
// WHY NO SDK. These apps run on Workers and on Vercel's Node runtime; the Sentry SDKs differ for each and pull
// in tracing, breadcrumbs and wrapping we don't use. One fetch of one event is all we need, and it behaves
// the same everywhere.
//
// RULES.
//  - No DSN set → nothing is sent, nothing throws. Safe to deploy before the project exists.
//  - It never throws and never waits more than 3 s; callers hand the promise to waitUntil or await it.
//  - No personal data: callers pass tags and context, never an email address, code or token.

export interface SentryConfig {
  /** The project's DSN (Sentry → Settings → Client Keys). Unset → reporting is off. */
  dsn?: string;
  /** `production` or `staging`. */
  environment?: string;
  /** The app the event comes from, e.g. `gcid-home`. */
  app: string;
}

export interface SentryEvent {
  /** What happened, in a sentence: the issue title in Sentry. */
  message: string;
  /** The underlying error, if any: its name, message and stack go on the event. */
  error?: unknown;
  /** `error` (default), `warning` or `fatal`. */
  level?: 'fatal' | 'error' | 'warning';
  /** Short, searchable values (route, provider, app id). */
  tags?: Record<string, string | number | boolean | undefined>;
  /** Anything else useful, never personal data. */
  extra?: Record<string, unknown>;
}

interface ParsedDsn { url: string; dsn: string }

function parseDsn(raw: string | undefined): ParsedDsn | null {
  const dsn = raw?.trim();
  if (!dsn) return null;
  try {
    const u = new URL(dsn);
    const project = u.pathname.replace(/^\/+|\/+$/g, '').split('/').pop();
    if (!u.username || !project) return null;
    const path = u.pathname.replace(/\/[^/]*\/?$/, '');
    return { dsn, url: `${u.protocol}//${u.host}${path}/api/${project}/envelope/?sentry_key=${u.username}&sentry_version=7` };
  } catch {
    return null;
  }
}

export function sentryEnabled(cfg: SentryConfig): boolean {
  return parseDsn(cfg.dsn) !== null;
}

const hex = (n: number) => Array.from(crypto.getRandomValues(new Uint8Array(n)), (b) => b.toString(16).padStart(2, '0')).join('');

/** Build the envelope body. Exported for tests. */
export function sentryEnvelope(cfg: SentryConfig, ev: SentryEvent, now = new Date()): { url: string; body: string } | null {
  const parsed = parseDsn(cfg.dsn);
  if (!parsed) return null;
  const eventId = hex(16);
  const err = ev.error instanceof Error ? ev.error : ev.error !== undefined ? new Error(String(ev.error)) : null;
  const tags: Record<string, string> = { app: cfg.app };
  for (const [k, v] of Object.entries(ev.tags ?? {})) if (v !== undefined) tags[k] = String(v).slice(0, 200);
  const event = {
    event_id: eventId,
    timestamp: now.getTime() / 1000,
    platform: 'javascript',
    level: ev.level ?? 'error',
    logger: cfg.app,
    environment: cfg.environment?.trim() || 'production',
    server_name: cfg.app,
    message: { formatted: ev.message },
    ...(err ? { exception: { values: [{ type: err.name || 'Error', value: err.message.slice(0, 2000) }] } } : {}),
    tags,
    extra: { ...(ev.extra ?? {}), ...(err?.stack ? { stack: err.stack.slice(0, 8000) } : {}) },
  };
  const body = [
    JSON.stringify({ event_id: eventId, sent_at: now.toISOString(), dsn: parsed.dsn }),
    JSON.stringify({ type: 'event' }),
    JSON.stringify(event),
  ].join('\n');
  return { url: parsed.url, body };
}

/** Report one event. Always resolves; also logs, so the event is in the platform's logs with or without Sentry. */
export async function reportToSentry(cfg: SentryConfig, ev: SentryEvent): Promise<void> {
  const detail = ev.error instanceof Error ? ev.error.message : ev.error !== undefined ? String(ev.error) : '';
  console.error(`[sentry] ${cfg.app}: ${ev.message}${detail ? ` — ${detail}` : ''}`, ev.tags ?? {});
  const env = sentryEnvelope(cfg, ev);
  if (!env) return;
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 3000);
    await fetch(env.url, { method: 'POST', headers: { 'content-type': 'application/x-sentry-envelope' }, body: env.body, signal: ctrl.signal })
      .catch(() => undefined)
      .finally(() => clearTimeout(timer));
  } catch {
    // Reporting must never break the request it reports on.
  }
}
