// THE EMAIL CHANNEL — spec 365, the app half.
//
// The port and the rules live in `@agenticprimitives/fabric/email`; the PROVIDERS live here, because a
// transport is a leaf binding that depends inward (ADR-0057) and the substrate must not know whether a
// deployment sends through an HTTP API or a platform binding.
//
// TWO INTEGRATIONS, deliberately:
//   · CLOUDFLARE EMAIL — the `send_email` binding, and the only rail that can also RECEIVE (Email
//     Routing calls this Worker's `email()` handler). Its honest limitation: a Worker may only send to
//     addresses verified in the account, so it is right for replies and estate mail and wrong for
//     inviting a stranger.
//   · SENDGRID — an HTTP API that will send to anyone, which is what an invitation needs.
//   · MAILGUN — the same shape as SendGrid, for a deployment whose operator already holds a Mailgun account.
// All behind one port, so a caller asks for "email" and the deployment decides which rail carries it.
import {
  firstAvailableSender, handleFromAddress, inboundEmailToMessage, isEmailAddress,
  type EmailSenderPort, type InboundEmailV1, type OutboundEmailV1,
} from '@agenticprimitives/fabric/email';

import { reportToSentry } from './sentry-report.js';

/** The bindings and secrets the two providers need. All optional: email is a capability a deployment
 *  HAS or does not, and the surfaces ask before they offer it. */
export interface EmailEnv {
  /** Cloudflare Email Service binding (`[[send_email]]`, `name = "SEND_EMAIL"`). Sends to ANY address from a
   *  domain onboarded to Email Sending (`wrangler email sending enable <zone>`); `EMAIL_FROM` must be on it. */
  SEND_EMAIL?: { send(msg: { to: string; from: { email: string; name?: string }; replyTo?: string; subject: string; text: string; html?: string; headers?: Record<string, string> }): Promise<{ messageId?: string } | void> };
  /** The display name mail goes out under. */
  EMAIL_FROM_NAME?: string;
  SENDGRID_API_KEY?: string;
  /** Mailgun sending key — a domain-scoped key, not the account key. */
  MAILGUN_API_KEY?: string;
  /** The Mailgun sending domain. Unset → the domain of `EMAIL_FROM`. */
  MAILGUN_DOMAIN?: string;
  /** `https://api.eu.mailgun.net` for an EU-region account. Unset → the US endpoint. */
  MAILGUN_API_BASE?: string;
  /** The verified sender address mail goes out as. Required by both rails. */
  EMAIL_FROM?: string;
  /** The zones whose mail this deployment answers for, comma-separated (`faithnet.me`). */
  EMAIL_ZONES?: string;
  /** Sentry (sentry-report.ts): a failover is reported there. Unset DSN -> logged only. */
  SENTRY_DSN?: string;
  SENTRY_ENVIRONMENT?: string;
}

/**
 * Cloudflare Email Service (2025+): `env.SEND_EMAIL.send({ to, from, subject, text, html })` from a domain
 * onboarded to Email Sending — any destination, no verified-address list. The earlier Email Workers
 * `EmailMessage` rail (verified destinations only) is gone: it could not invite a stranger, which is the
 * one thing an invitation must do.
 */
export function cloudflareSender(env: EmailEnv): EmailSenderPort {
  return {
    name: 'cloudflare',
    available: () => !!env.SEND_EMAIL && !!env.EMAIL_FROM?.trim(),
    async send(msg) {
      const from = env.EMAIL_FROM!.trim();
      try {
        const res = await env.SEND_EMAIL!.send({
          to: msg.to,
          from: { email: from, ...(env.EMAIL_FROM_NAME?.trim() ? { name: env.EMAIL_FROM_NAME.trim() } : {}) },
          // Reply-To is a first-class field on the Email Service binding (a hand-set header is refused).
          ...((msg as { replyTo?: string }).replyTo ? { replyTo: (msg as { replyTo?: string }).replyTo } : {}),
          subject: msg.subject, text: msg.text,
          ...(msg.html ? { html: msg.html } : {}),
          ...(msg.inReplyTo ? { headers: { 'In-Reply-To': msg.inReplyTo, References: msg.inReplyTo } } : {}),
        });
        const messageId = res && typeof res === 'object' && typeof res.messageId === 'string' ? res.messageId : undefined;
        return { ok: true, via: 'cloudflare', ...(messageId ? { messageId } : {}) };
      } catch (e) {
        const why = e instanceof Error ? e.message : String(e);
        // "Invalid email address: Invalid email domain" is about the RECIPIENT (an address that cannot receive mail);
        // only an onboarding/enablement refusal is about the sender. They used to share one message (2026-10-15).
        const recipient = /invalid email (address|domain)|recipient/i.test(why);
        const sender = !recipient && /onboard|not enabled|sending.*(disabled|not allowed)/i.test(why);
        return {
          ok: false,
          via: 'cloudflare',
          error: recipient
            ? `that address can't receive email — check it for a typo (${why})`
            : sender
              ? `${from}'s domain is not onboarded to Email Sending (wrangler email sending enable): ${why}`
              : why,
        };
      }
    },
  };
}

export function sendgridSender(env: EmailEnv): EmailSenderPort {
  return {
    name: 'sendgrid',
    available: () => !!env.SENDGRID_API_KEY?.trim() && !!env.EMAIL_FROM?.trim(),
    async send(msg) {
      try {
        const res = await fetch('https://api.sendgrid.com/v3/mail/send', {
          method: 'POST',
          headers: { 'content-type': 'application/json', authorization: `Bearer ${env.SENDGRID_API_KEY!.trim()}` },
          body: JSON.stringify({
            personalizations: [{ to: [{ email: msg.to }] }],
            from: { email: env.EMAIL_FROM!.trim(), ...(env.EMAIL_FROM_NAME?.trim() ? { name: env.EMAIL_FROM_NAME.trim() } : {}) },
            ...((msg as { replyTo?: string }).replyTo ? { reply_to: { email: (msg as { replyTo?: string }).replyTo } } : {}),
            subject: msg.subject,
            content: [{ type: 'text/plain', value: msg.text }, ...(msg.html ? [{ type: 'text/html', value: msg.html }] : [])],
          }),
        });
        if (!res.ok) return { ok: false, via: 'sendgrid', error: `sendgrid ${res.status}` };
        return { ok: true, via: 'sendgrid', ...(res.headers.get('x-message-id') ? { messageId: res.headers.get('x-message-id')! } : {}) };
      } catch (e) {
        return { ok: false, via: 'sendgrid', error: e instanceof Error ? e.message : 'send failed' };
      }
    },
  };
}

export function mailgunSender(env: EmailEnv): EmailSenderPort {
  return {
    name: 'mailgun',
    available: () => !!env.MAILGUN_API_KEY?.trim() && !!env.EMAIL_FROM?.trim(),
    async send(msg) {
      const from = env.EMAIL_FROM!.trim();
      const domain = env.MAILGUN_DOMAIN?.trim() || from.split('@')[1] || '';
      const base = (env.MAILGUN_API_BASE?.trim() || 'https://api.mailgun.net').replace(/\/$/, '');
      const replyTo = (msg as { replyTo?: string }).replyTo;
      const form = new URLSearchParams({
        from: env.EMAIL_FROM_NAME?.trim() ? `${env.EMAIL_FROM_NAME.trim()} <${from}>` : from,
        to: msg.to, subject: msg.subject, text: msg.text,
      });
      if (msg.html) form.set('html', msg.html);
      if (replyTo) form.set('h:Reply-To', replyTo);
      if (msg.inReplyTo) { form.set('h:In-Reply-To', msg.inReplyTo); form.set('h:References', msg.inReplyTo); }
      try {
        const res = await fetch(`${base}/v3/${encodeURIComponent(domain)}/messages`, {
          method: 'POST',
          headers: { authorization: `Basic ${btoa(`api:${env.MAILGUN_API_KEY!.trim()}`)}` },
          body: form,
        });
        const body = (await res.json().catch(() => ({}))) as { id?: string; message?: string };
        if (!res.ok) return { ok: false, via: 'mailgun', error: `mailgun ${res.status}${body.message ? `: ${body.message}` : ''}` };
        return { ok: true, via: 'mailgun', ...(body.id ? { messageId: body.id } : {}) };
      } catch (e) {
        return { ok: false, via: 'mailgun', error: e instanceof Error ? e.message : 'send failed' };
      }
    },
  };
}

/** A refusal about the RECIPIENT (a mistyped or dead address): every rail would refuse it, so no failover. */
const RECIPIENT_ERROR = /not a valid address|invalid (email )?(address|domain)|can't receive email|recipient/i;

/** Error text for a report: provider messages can quote the address, and no address goes to Sentry. */
const scrub = (t: string | undefined) => (t ?? '').replace(/[^\s<>"'@]+@[^\s<>"'@]+/g, '<address>').slice(0, 500);

/**
 * FAILOVER (GC, 2026-10-21). Rails in order; when one REFUSES a message or cannot be reached, the next
 * available rail sends it, and the failover is logged and reported to Sentry.
 *
 * This is a deliberate exception to the package's "preference, not fallback" rule (ADR-0013), agreed by
 * Paul and Ryan after Cloudflare's unpublished daily quota stopped every sign-in code on 2026-10-20. The
 * rule guards against a message delivered twice. Here the cost is small: a sign-in code is reused while
 * it is valid, so a duplicate carries the same code, and every failover is reported, so nothing hides.
 * A refusal about the recipient is returned as is: every rail would refuse it.
 */
export function failoverSender(
  rails: readonly EmailSenderPort[],
  onFailover: (event: { failed: string; error: string; next: string; delivered: boolean; nextError?: string }) => Promise<void> | void,
): EmailSenderPort {
  const [first] = rails;
  if (!first) throw new Error('failoverSender needs at least one rail');
  return {
    name: first.name,
    available: () => rails.some((r) => r.available()),
    async send(msg) {
      let last: Awaited<ReturnType<EmailSenderPort['send']>> | null = null;
      let failed: { name: string; error: string } | null = null;
      for (const rail of rails) {
        if (!rail.available()) continue;
        const result = await rail.send(msg).catch((e: unknown) => ({ ok: false as const, via: rail.name, error: e instanceof Error ? e.message : String(e) }));
        if (failed) {
          await Promise.resolve(onFailover({ failed: failed.name, error: failed.error, next: rail.name, delivered: result.ok, ...(result.ok ? {} : { nextError: result.error ?? '' }) })).catch(() => undefined);
        }
        if (result.ok) return result;
        last = result;
        if (RECIPIENT_ERROR.test(result.error ?? '')) return result;
        failed = { name: rail.name, error: result.error ?? 'send failed' };
      }
      return last ?? { ok: false, error: 'no email rail is configured' };
    },
  };
}

/**
 * The rail this deployment sends on, or null. Mailgun, then SendGrid, then Cloudflare: an HTTP provider
 * first, because a new Cloudflare account's daily quota is unpublished and grows only with reputation.
 * With more than one configured, a refusal fails over to the next (failoverSender above).
 */
export function emailSender(env: EmailEnv): EmailSenderPort | null {
  const rails = [mailgunSender(env), sendgridSender(env), cloudflareSender(env)].filter((r) => r.available());
  if (rails.length <= 1) return firstAvailableSender(rails);
  return failoverSender(rails, (ev) => {
    const what = ev.delivered ? `${ev.failed} failed, sent via ${ev.next}` : `${ev.failed} failed and ${ev.next} failed too`;
    return reportToSentry(
      { app: 'gcid-runtime', dsn: env.SENTRY_DSN, environment: env.SENTRY_ENVIRONMENT },
      {
        message: `email failover: ${what}`,
        level: ev.delivered ? 'warning' : 'error',
        tags: { failed: ev.failed, next: ev.next, delivered: ev.delivered },
        extra: { error: scrub(ev.error), ...(ev.nextError !== undefined ? { nextError: scrub(ev.nextError) } : {}) },
      },
    );
  });
}

export function emailZones(env: EmailEnv): string[] {
  return (env.EMAIL_ZONES ?? '').split(',').map((z) => z.trim().toLowerCase()).filter(Boolean);
}

/** What the inbound handler needs from the app, injected so this file stays testable and thin. */
export interface InboundDeps {
  /** `alice` → her agent address, from the naming service. Null when nobody holds the name. */
  resolveHandle: (handle: string) => Promise<string | null>;
  /** Admit a message into the recipient's own inbox. The ONE thing inbound mail may do. */
  admit: (input: { recipient: string; subject: string; bodyText: string; claimedFrom: string; messageId?: string }) => Promise<{ ok: boolean; error?: string }>;
}

export type InboundOutcome =
  | { ok: true; recipient: string }
  | { ok: false; reason: 'not-our-zone' | 'no-such-agent' | 'not-admitted'; detail?: string };

/**
 * AN EMAIL ARRIVES — spec 365 rule 1: it becomes a MESSAGE and can never become an act.
 *
 * Routed by the address it was sent TO, resolved through the naming service. A name nobody holds is a
 * refusal, not a guess at the nearest one: delivering a stranger's mail to whoever has a similar handle
 * is the worst thing this path could do.
 *
 * There is deliberately no branch here that reads the body for instructions. Everything a person can do
 * from the resulting thread, they do from their own surface, under their own mandate.
 */
export async function admitInboundEmail(mail: InboundEmailV1, zones: readonly string[], deps: InboundDeps): Promise<InboundOutcome> {
  const handle = handleFromAddress(mail.to, zones);
  if (!handle) return { ok: false, reason: 'not-our-zone' };
  const agent = await deps.resolveHandle(handle).catch(() => null);
  if (!agent) return { ok: false, reason: 'no-such-agent', detail: handle };
  const shaped = inboundEmailToMessage(mail);
  const out = await deps.admit({
    recipient: agent.toLowerCase(),
    subject: shaped.subject,
    bodyText: shaped.bodyText,
    claimedFrom: shaped.claimedFrom,
    ...(mail.messageId ? { messageId: mail.messageId } : {}),
  });
  return out.ok ? { ok: true, recipient: agent.toLowerCase() } : { ok: false, reason: 'not-admitted', ...(out.error ? { detail: out.error } : {}) };
}

export { isEmailAddress };
