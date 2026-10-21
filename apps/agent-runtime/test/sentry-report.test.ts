import { afterEach, describe, expect, it, vi } from 'vitest';
import { reportToSentry, sentryEnabled, sentryEnvelope } from '../src/sentry-report.js';

const DSN = 'https://abc123@o4500.ingest.us.sentry.io/4501';

describe('sentry reporting', () => {
  afterEach(() => vi.restoreAllMocks());

  it('is off without a DSN, and with a malformed one', () => {
    expect(sentryEnabled({ app: 'x' })).toBe(false);
    expect(sentryEnabled({ app: 'x', dsn: 'not a url' })).toBe(false);
    expect(sentryEnvelope({ app: 'x', dsn: '' }, { message: 'm' })).toBeNull();
    expect(sentryEnabled({ app: 'x', dsn: DSN })).toBe(true);
  });

  it('posts one event to the project envelope endpoint', () => {
    const env = sentryEnvelope({ app: 'gcid-home', dsn: DSN, environment: 'staging' }, {
      message: 'sign-in code send failed', error: new Error('quota'), tags: { route: 'email-start', skip: undefined },
    })!;
    expect(env.url).toBe('https://o4500.ingest.us.sentry.io/api/4501/envelope/?sentry_key=abc123&sentry_version=7');
    const [header, item, event] = env.body.split('\n').map((l) => JSON.parse(l));
    expect(header.dsn).toBe(DSN);
    expect(item.type).toBe('event');
    expect(event.environment).toBe('staging');
    expect(event.message.formatted).toBe('sign-in code send failed');
    expect(event.exception.values[0].value).toBe('quota');
    expect(event.tags).toEqual({ app: 'gcid-home', route: 'email-start' });
  });

  it('never throws, even when Sentry is unreachable', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
    const f = vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('down'));
    await expect(reportToSentry({ app: 'x', dsn: DSN }, { message: 'm' })).resolves.toBeUndefined();
    expect(f).toHaveBeenCalledOnce();
  });

  it('sends nothing without a DSN', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
    const f = vi.spyOn(globalThis, 'fetch');
    await reportToSentry({ app: 'x' }, { message: 'm' });
    expect(f).not.toHaveBeenCalled();
  });
});
