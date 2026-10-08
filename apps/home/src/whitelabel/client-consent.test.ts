/**
 * Per-client consent wording (RelyingApp.consent) — Gather27 speaks plainly; nobody else moves.
 *
 * The shared `delegationTemplates` / `copy` are every app's on this Home, so the override is the ONLY
 * way one app's sheet changes. This suite is the blast-radius proof: gather-app gets its own lines, and
 * every other registered client resolves to the shared default — the same object, not a lookalike.
 */
import { describe, expect, it } from 'vitest';

import { whitelabel } from './config';
import { clientCopy, clientProgressText, orgCreateText, signedInLabel, switchAccountLabel, withClientConsent } from './client-consent';
import { sharesEmailClaim } from './provisioning';

const gather = whitelabel.relyingApps.find((a) => a.client_id === 'gather-app')!;
const others = whitelabel.relyingApps.filter((a) => a.client_id !== 'gather-app');
const shared = whitelabel.delegationTemplates;
const ADDR = '0x6a25000000000000000000000000000000f058';

describe('gather-app — its own words', () => {
  it('is named Gather27 (one word) and says what it is for', () => {
    expect(gather.name).toBe('Gather27');
    expect(gather.description).toBe('Find and list Gather groups.');
  });

  for (const id of ['site-login', 'org-create']) {
    it(`${id}: the three plain lines and no "cannot" block`, () => {
      const t = withClientConsent(shared[id]!, gather, id);
      expect(t.canDo).toEqual(['Sign you in to Gather27', 'See your name and email', 'Set up your church’s listing']);
      expect(t.hideCannotDo).toBe(true);
      expect(t.cannotDo).toEqual([]);
      expect(t.expiryDays).toBe(shared[id]!.expiryDays);
    });
  }

  it('still discloses the email it receives (the override replaces the email-claim helper line)', () => {
    expect(sharesEmailClaim(gather)).toBe(true);
    for (const own of Object.values(gather.consent!.templates!)) {
      expect(own.canDo.some((l) => /email/i.test(l))).toBe(true);
    }
  });

  it('none of its lines speak the Home’s vocabulary', () => {
    const lines = Object.values(gather.consent!.templates!).flatMap((t) => [...t.canDo, ...(t.cannotDo ?? [])]);
    for (const l of lines) expect(l).not.toMatch(/custod|funds|recovery|keys?\b|chain|missional|sign-in methods/i);
  });

  it('keeps the shared text for a template it did not word (service-agent-wire)', () => {
    const t = shared['service-agent-wire'];
    if (t) expect(withClientConsent(t, gather, 'service-agent-wire')).toBe(t);
  });

  it('signs in as the email, falling back to the short address only without one', () => {
    expect(signedInLabel(gather, { email: 'host@church.org', address: ADDR })).toBe('host@church.org');
    expect(signedInLabel(gather, { email: '', address: ADDR })).toBe('0x6a25…f058');
  });

  it('keeps an account switch, worded for email', () => {
    expect(switchAccountLabel(gather, 'ana')).toBe('Not you? Use a different email');
  });

  it('the org-create prose is about the church listing, not a home or a name', () => {
    const vars = { app: 'Gather27', org: 'Grace Church' };
    expect(orgCreateText(gather, 'explainer', vars, 'SHARED')).toBe(
      'This single approval sets up Grace Church. Your church gets its own listing page on Gather27. Nothing beyond that.',
    );
    expect(orgCreateText(gather, 'disconnect', vars, 'SHARED')).toBe('You can disconnect Gather27 any time from your Great Commission ID.');
    expect(orgCreateText(gather, 'receipt', vars, 'SHARED')).toBe('Your church is set up.');
    for (const k of ['explainer', 'disconnect', 'receipt'] as const) {
      expect(orgCreateText(gather, k, vars, 'SHARED')).not.toMatch(/\bhome\b|chain|custod|Impact|name is claimed|claims its name/i);
    }
  });

  it('busy note and chain narration are plain', () => {
    expect(clientCopy(gather, 'portalStepBusy')).toBe('Signing you in…');
    expect(clientProgressText(gather, 'Confirming it on the chain…')).toBe('Confirming…');
    expect(clientProgressText(gather, 'Signing your permission…')).toBe('Signing your permission…');
  });
});

describe('every other client — the shared defaults, unchanged', () => {
  it('first non-gather client resolves to the shared templates themselves', () => {
    const first = others[0]!;
    for (const [id, t] of Object.entries(shared)) expect(withClientConsent(t, first, id)).toBe(t);
  });

  it('no other client carries consent wording or a description (add one deliberately, then update this)', () => {
    for (const app of others) {
      expect(app.consent, app.client_id).toBeUndefined();
      expect(app.description, app.client_id).toBeUndefined();
    }
  });

  it('copy, progress text and "Signed in as" are the shared ones', () => {
    for (const app of others) {
      expect(clientCopy(app, 'portalStepBusy')).toBe(whitelabel.copy.portalStepBusy);
      expect(clientProgressText(app, 'Confirming it on the chain…')).toBe('Confirming it on the chain…');
      expect(signedInLabel(app, { email: 'x@y.z', name: 'ana', address: ADDR })).toBe('ana');
      expect(signedInLabel(app, { email: 'x@y.z', address: ADDR })).toBe('0x6a25…f058');
      expect(switchAccountLabel(app, 'ana')).toBe('Not ana? Use a different custodian');
      expect(switchAccountLabel(app, undefined)).toBe('Not you? Use a different custodian');
      for (const k of ['explainer', 'disconnect', 'receipt'] as const) {
        expect(orgCreateText(app, k, { app: 'X', org: 'Y' }, 'SHARED')).toBe('SHARED');
      }
    }
  });

  it('an unknown / absent client is the shared default too', () => {
    expect(withClientConsent(shared['site-login']!, undefined, 'site-login')).toBe(shared['site-login']);
    expect(withClientConsent(shared['site-login']!, gather, undefined)).toBe(shared['site-login']);
  });
});
