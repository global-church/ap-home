// The Home's Sentry settings (GC, 2026-10-21). SENTRY_DSN is set per Vercel project (staging and production
// are separate projects, both deployed as Vercel "production"), so SENTRY_ENVIRONMENT names which one it is.
import { reportToSentry, type SentryEvent } from './sentry-report';

const env = (k: string): string | undefined => (typeof process !== 'undefined' ? process.env?.[k]?.trim() : undefined) || undefined;

export function reportHomeError(ev: SentryEvent): Promise<void> {
  return reportToSentry({ app: 'gcid-home', dsn: env('SENTRY_DSN'), environment: env('SENTRY_ENVIRONMENT') ?? env('VERCEL_ENV') }, ev);
}

/** What a person sees when their sign-in code could not be sent. The provider's own error goes to Sentry, not to them. */
export const CODE_SEND_FAILED = "We couldn't send your code right now. Please try again in a few minutes.";
