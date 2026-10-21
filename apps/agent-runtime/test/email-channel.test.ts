import { describe, it, expect, vi, afterEach } from 'vitest';
import { emailSender, failoverSender, mailgunSender, sendgridSender } from '../src/email-channel.js';

const msg = { to: 'host@example.org', subject: '123456 is your GCID sign-in code', text: 'Your code is 123456.', html: '<p>123456</p>', replyTo: 'help@gather27.com' };
const cfBinding = { send: async () => ({ messageId: 'cf' }) };

afterEach(() => { vi.unstubAllGlobals(); });

describe('emailSender — which rail', () => {
  it('prefers Mailgun, then SendGrid, then Cloudflare', () => {
    const base = { EMAIL_FROM: 'sign-in@gcid.me', SEND_EMAIL: cfBinding };
    expect(emailSender(base)?.name).toBe('cloudflare');
    expect(emailSender({ ...base, SENDGRID_API_KEY: 'sg' })?.name).toBe('sendgrid');
    expect(emailSender({ ...base, SENDGRID_API_KEY: 'sg', MAILGUN_API_KEY: 'mg' })?.name).toBe('mailgun');
  });
  it('has no rail without a sender address', () => {
    expect(emailSender({ MAILGUN_API_KEY: 'mg' })).toBeNull();
  });
});

describe('mailgunSender', () => {
  it('posts the message to the sending domain with Reply-To and the display name', async () => {
    const calls: Array<{ url: string; init: RequestInit }> = [];
    vi.stubGlobal('fetch', async (url: string, init: RequestInit) => { calls.push({ url, init }); return new Response(JSON.stringify({ id: '<abc@gcid.me>', message: 'Queued' })); });
    const r = await mailgunSender({ MAILGUN_API_KEY: 'key-1', EMAIL_FROM: 'sign-in@gcid.me', EMAIL_FROM_NAME: 'GCID' }).send(msg as never);
    expect(r).toEqual({ ok: true, via: 'mailgun', messageId: '<abc@gcid.me>' });
    expect(calls[0]!.url).toBe('https://api.mailgun.net/v3/gcid.me/messages');
    expect((calls[0]!.init.headers as Record<string, string>).authorization).toBe(`Basic ${btoa('api:key-1')}`);
    const form = calls[0]!.init.body as URLSearchParams;
    expect(form.get('from')).toBe('GCID <sign-in@gcid.me>');
    expect(form.get('to')).toBe('host@example.org');
    expect(form.get('h:Reply-To')).toBe('help@gather27.com');
    expect(form.get('html')).toBe('<p>123456</p>');
  });
  it('honours an explicit domain and the EU endpoint', async () => {
    const calls: string[] = [];
    vi.stubGlobal('fetch', async (url: string) => { calls.push(url); return new Response('{}'); });
    await mailgunSender({ MAILGUN_API_KEY: 'k', EMAIL_FROM: 'a@gcid.me', MAILGUN_DOMAIN: 'mg.gcid.me', MAILGUN_API_BASE: 'https://api.eu.mailgun.net/' }).send(msg as never);
    expect(calls[0]).toBe('https://api.eu.mailgun.net/v3/mg.gcid.me/messages');
  });
  it('reports the provider refusal rather than claiming it went', async () => {
    vi.stubGlobal('fetch', async () => new Response(JSON.stringify({ message: 'Domain not found' }), { status: 404 }));
    const r = await mailgunSender({ MAILGUN_API_KEY: 'k', EMAIL_FROM: 'a@gcid.me' }).send(msg as never);
    expect(r).toEqual({ ok: false, via: 'mailgun', error: 'mailgun 404: Domain not found' });
  });
});

describe('sendgridSender', () => {
  it('carries Reply-To', async () => {
    let body: Record<string, unknown> = {};
    vi.stubGlobal('fetch', async (_u: string, init: RequestInit) => { body = JSON.parse(String(init.body)); return new Response(null, { status: 202 }); });
    await sendgridSender({ SENDGRID_API_KEY: 'sg', EMAIL_FROM: 'sign-in@gcid.me' }).send(msg as never);
    expect(body.reply_to).toEqual({ email: 'help@gather27.com' });
  });
});

describe('failover (GC, 2026-10-21): Mailgun first, Cloudflare when Mailgun refuses', () => {
  const rail = (name: string, result: { ok: boolean; error?: string } | Error) => {
    const sent: unknown[] = [];
    return {
      sent,
      port: {
        name, available: () => true,
        send: async (m: unknown) => { sent.push(m); if (result instanceof Error) throw result; return { ...result, via: name }; },
      },
    };
  };

  it('a delivered message goes out once, on the first rail, with no failover', async () => {
    const mg = rail('mailgun', { ok: true }); const cf = rail('cloudflare', { ok: true });
    const events: unknown[] = [];
    const r = await failoverSender([mg.port, cf.port], (e) => void events.push(e)).send(msg as never);
    expect(r.via).toBe('mailgun');
    expect(cf.sent).toHaveLength(0);
    expect(events).toHaveLength(0);
  });

  it('a refusal or an unreachable provider fails over, and the failover is reported', async () => {
    for (const failure of [{ ok: false, error: 'mailgun 401: Forbidden' }, new Error('fetch failed')]) {
      const mg = rail('mailgun', failure); const cf = rail('cloudflare', { ok: true });
      const events: Array<{ failed: string; next: string; delivered: boolean }> = [];
      const r = await failoverSender([mg.port, cf.port], (e) => void events.push(e)).send(msg as never);
      expect(r.ok).toBe(true);
      expect(r.via).toBe('cloudflare');
      expect(events).toEqual([expect.objectContaining({ failed: 'mailgun', next: 'cloudflare', delivered: true })]);
    }
  });

  it('a bad recipient address does not fail over: every rail would refuse it', async () => {
    const mg = rail('mailgun', { ok: false, error: "mailgun 400: 'to' parameter is not a valid address" }); const cf = rail('cloudflare', { ok: true });
    const r = await failoverSender([mg.port, cf.port], () => {}).send(msg as never);
    expect(r.ok).toBe(false);
    expect(cf.sent).toHaveLength(0);
  });

  it('when every rail fails, the last error comes back and the double failure is reported', async () => {
    const mg = rail('mailgun', { ok: false, error: 'mailgun 503' }); const cf = rail('cloudflare', { ok: false, error: 'daily sending quota exceeded' });
    const events: Array<{ delivered: boolean }> = [];
    const r = await failoverSender([mg.port, cf.port], (e) => void events.push(e)).send(msg as never);
    expect(r).toMatchObject({ ok: false, error: 'daily sending quota exceeded' });
    expect(events).toEqual([expect.objectContaining({ delivered: false })]);
  });

  it('emailSender fails over from Mailgun to Cloudflare when both are configured', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ message: 'Forbidden' }), { status: 401 })));
    vi.spyOn(console, 'error').mockImplementation(() => {});
    const r = await emailSender({ EMAIL_FROM: 'sign-in@gcid.me', SEND_EMAIL: cfBinding, MAILGUN_API_KEY: 'mg' })!.send(msg as never);
    expect(r).toMatchObject({ ok: true, via: 'cloudflare' });
  });

  it('with one rail configured there is nothing to fail over to', () => {
    expect(emailSender({ EMAIL_FROM: 'sign-in@gcid.me', MAILGUN_API_KEY: 'mg' })?.name).toBe('mailgun');
  });
});
