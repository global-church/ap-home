'use client';
// Email sign-in / add-email card (email-auth Phase 1b). Two-step: enter email → get a 6-digit code →
// verify. Behavior depends on whether there's a session: signed-in ⇒ LINK (add email as a login method),
// anonymous ⇒ ISSUE a login-grade session (or BOOTSTRAP if there's no home for that email yet).
//
// EXISTING-HOME INTERSTITIAL (live 2026-07-20, psk-4): one email = ONE canonical home (ADR-0010 —
// the KMS sub is SHA-256(email)), so verifying an already-bound email OPENS that home; it can never
// found a second one. Previously that silently dropped the name the member chose in the journey
// (`pendingHomeName`) and dumped them into the old (often nameless) home with no explanation. Now,
// when a chosen name is pending and the email resolves to an existing home, the member decides:
// continue into the existing home (optionally claiming the chosen name for it when it has none), or
// go back and use a different email for the new named home.
//
// PASSKEY STEP (2026-07-21): after every successful anonymous email sign-in ON THE MEMBER'S OWN
// SUBDOMAIN, offer to create a device passkey — added on-chain as a custodian under the email KMS
// session (addPasskeyCredential: server-signed authorization, ONE device prompt) — so subsequent
// visits sign in with face/fingerprint/PIN instead of an emailed code (the welcome-back screen
// offers passkey once `hasPasskey` is true on-chain). Email stays the fallback: when a passkey
// breaks, the member signs in by code and the offer re-appears — the fresh key OVERWRITES the
// broken one in the authenticator (stable userHandle per (rpId, label)). Subdomain-gated because
// passkeys are RP-scoped (spec 229 P5): a key created here is only findable on THIS host, so the
// offer shows only where the member will return.
import { useState } from 'react';
import { useSession } from '../../context/session';
import { WorkingBar } from '../onboarding/WorkingBar';
import { secureHomeNoName, activateVault, signHashFor } from '../../home/onboarding';
import { addPasskeyCredential, claimName, fetchProfile } from '../../connect-client';
import { CENTRAL_AUTH_DOMAIN, nameLabel } from '../../lib/domain';
import { seedImpactProfileFields } from '../../profile-store';
import { rememberVerifiedEmail } from '../../lib/verified-email';
import type { Address } from '@agenticprimitives/types';
import { whitelabel } from '../../whitelabel/config';

/** Should this host offer the passkey step for a home named `homeName`? Only on a member subdomain
 *  (the passkey's RP = this host — it must be where the member returns), and only when the subdomain
 *  IS the home's name (or the home is nameless — the entry flow claims this subdomain's name for it). */
function passkeyOfferHost(homeName: string | null | undefined): boolean {
  if (typeof window === 'undefined') return false;
  // A deployment that does not offer passkeys as a way in never asks for one after the code either — email IS
  // the credential here (2026-09-13: "email connect took me into a passkey challenge that I do not want").
  if (!whitelabel.onboarding.credentialMethods.includes('passkey')) return false;
  const h = window.location.hostname;
  if (h === CENTRAL_AUTH_DOMAIN || !h.endsWith(`.${CENTRAL_AUTH_DOMAIN}`)) return false;
  const label = h.slice(0, -(CENTRAL_AUTH_DOMAIN.length + 1));
  if (!label || label === 'www' || label.includes('.')) return false;
  const home = homeName ? nameLabel(homeName) : '';
  return !home || home === label;
}

export function EmailAuthCard({ onLinked, busyNote = 'Securing your home…' }: {
  /** Called with the verified address/number once it is LINKED to this home (spec 422 §3.3 records it as a channel). */
  onLinked?: (value: string) => void;
  /** The note while a new email home is made. A relying app's sign-in passes its own words
   *  (whitelabel/client-consent.ts `clientCopy(…, 'portalStepBusy')`); everywhere else keeps the default. */
  busyNote?: string;
}) {
  const { session, openSession } = useSession();
  const [step, setStep] = useState<'email' | 'code' | 'existing-home' | 'passkey-offer'>('email');
  const [email, setEmail] = useState('');
  const [otp, setOtp] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  /** The issued token held while the member decides between their EXISTING home and the name they
   *  chose (see the existing-home interstitial below). */
  const [pendingToken, setPendingToken] = useState<string | null>(null);
  const [chosenName, setChosenName] = useState<string>('');
  const [existingName, setExistingName] = useState<string>('');
  const [existingAddr, setExistingAddr] = useState<string>('');
  /** Held while the passkey-offer step is up (the session opens AFTER the offer resolves —
   *  opening it first would navigate away and unmount this card). */
  const [pkToken, setPkToken] = useState<string | null>(null);
  const [pkAgent, setPkAgent] = useState<string>('');

  const start = async () => {
    setBusy(true); setErr(null); setNote(null);
    try {
      const r = await fetch('/connect/email/start', {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ email: email.trim().toLowerCase() }),
      });
      const d = (await r.json().catch(() => ({}))) as { ok?: boolean; delivery?: string; error?: string; devCode?: string };
      if (!r.ok || !d.ok) throw new Error(d.error ?? 'could not send the code');
      setStep('code');
      setNote(d.delivery === 'logged'
        ? (d.devCode ? `Email isn’t configured (dev) — your code is ${d.devCode}.` : 'Email sending isn’t configured yet — the code was logged server-side (dev).')
        : `We sent a 6-digit code to ${email.trim()}.`);
    } catch (e) { setErr(e instanceof Error ? e.message : String(e)); } finally { setBusy(false); }
  };

  /** Open the session + seed the verified email (the shared tail of every issued path). */
  const finishSignIn = async (token: string, knownAddr?: string) => {
    // Remember it for this window BEFORE the session opens (opening it re-renders the window into the
    // consent screen, which reads it to say "Signed in as <email>" — lib/verified-email.ts).
    rememberVerifiedEmail(knownAddr, email);
    const p = await openSession(token, 'email', false);
    onLinked?.(email.trim().toLowerCase());
    // Metadata-tiers doctrine: the VERIFIED email is tier-1 PII — seed the private vault profile
    // (fill-only-empty, best-effort; the member edits/removes it on /profile anytime).
    const addr = p?.agent?.split(':').pop();
    if (addr) rememberVerifiedEmail(addr, email);
    if (addr) void seedImpactProfileFields(addr as `0x${string}`, { email: email.trim().toLowerCase() });
  };

  /** Shared tail of every ANONYMOUS issued path: on the member's own subdomain, pause on the
   *  passkey-offer step (create a device passkey → custodian on-chain → future visits are one-tap)
   *  before opening the session; elsewhere / after "not now", sign straight in. Re-runs on every
   *  email sign-in — a broken passkey's owner falls back to the code and gets a fresh key here. */
  const routeAfterIssued = async (token: string, hint?: { name?: string | null; addr?: string | null }) => {
    let name = hint?.name ?? null;
    let addr = hint?.addr ?? '';
    if (!addr) {
      const p = await fetchProfile(token).catch(() => null);
      name = p?.name ?? null;
      addr = p?.agent?.split(':').pop() ?? '';
    }
    if (addr && passkeyOfferHost(name)) {
      setPkToken(token);
      setPkAgent(addr);
      setNote(null);
      setStep('passkey-offer');
      return;
    }
    await finishSignIn(token, addr);
  };

  /** Passkey-offer action — ONE device prompt creates the key; the email KMS custodian signs the
   *  on-chain addPasskey (server-signed, no second gesture). Failure keeps the session path open:
   *  the member continues with email and the offer returns next time. */
  const createPasskeyNow = async () => {
    if (!pkToken || !pkAgent) return;
    setBusy(true); setErr(null);
    try {
      setNote('Confirm with your device…');
      const authorize = await signHashFor('email', pkAgent as Address, { token: pkToken });
      const res = await addPasskeyCredential(pkAgent as Address, authorize, (s) => setNote(s));
      if (!res.ok) throw new Error(res.error);
      setNote('Passkey ready — next time this device signs you in with a tap.');
      await finishSignIn(pkToken, pkAgent);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally { setBusy(false); }
  };

  const skipPasskey = async () => {
    if (!pkToken) return;
    setBusy(true); setErr(null);
    try {
      await finishSignIn(pkToken, pkAgent);
    } catch (e) { setErr(e instanceof Error ? e.message : String(e)); setBusy(false); }
  };

  const verify = async () => {
    setBusy(true); setErr(null);
    try {
      const r = await fetch('/connect/email/verify', {
        method: 'POST',
        headers: { 'content-type': 'application/json', ...(session ? { authorization: `Bearer ${session.token}` } : {}) },
        body: JSON.stringify({ email: email.trim().toLowerCase(), otp: otp.trim() }),
      });
      const d = (await r.json().catch(() => ({}))) as { status?: string; token?: string; custody?: boolean; error?: string };
      if (!r.ok) throw new Error(d.error ?? 'verification failed');
      if (d.status === 'linked') {
        const linked = email.trim().toLowerCase();
        setStep('email'); setEmail(''); setOtp(''); setNote('Email added — it opens this home and is where we tell you about changes.');
        onLinked?.(linked);
      } else if (d.status === 'issued' && d.token) {
        if (d.custody) {
          // Email-bootstrap: this email owns a KMS-custodied home. Secure it on-chain FIRST (demo-a2a
          // derives + holds the per-subject key — no device gesture), then open the session so the portal
          // loads a deployed, resolvable home.
          setNote(busyNote);
          const res = await secureHomeNoName({ token: d.token }, { claimPendingNameVia: 'email' });
          if (!res.ok) throw new Error(res.error);
          void activateVault(res.home.address, 'email', { token: d.token }); // spec 278 — best-effort vault
          await routeAfterIssued(d.token, { name: res.home.name || null, addr: res.home.address });
          return;
        }
        // EXISTING home (this email is already bound to a canonical SA — ADR-0010: it opens that home,
        // never founds a second). If the member chose a name in this journey, don't silently drop it:
        // show the interstitial so they decide (continue / name the home / different email).
        const pending = typeof sessionStorage !== 'undefined' ? sessionStorage.getItem('pendingHomeName') : null;
        if (pending) {
          const profile = await fetchProfile(d.token);
          const already = profile?.name ?? '';
          const chosen = nameLabel(pending) || pending;
          if (already && (nameLabel(already) || already) === (nameLabel(pending) || pending)) {
            // The existing home IS the chosen name — nothing to decide.
            sessionStorage.removeItem('pendingHomeName');
            await routeAfterIssued(d.token, { name: already, addr: profile?.agent?.split(':').pop() ?? '' });
            return;
          }
          setPendingToken(d.token);
          setChosenName(chosen);
          setExistingName(already);
          setExistingAddr(profile?.agent?.split(':').pop() ?? '');
          setStep('existing-home');
          return;
        }
        await routeAfterIssued(d.token);
      } else if (d.status === 'bootstrap') {
        setErr('We couldn’t set up a home for this email automatically — sign up with a passkey or Google, then add email.');
      }
    } catch (e) { setErr(e instanceof Error ? e.message : String(e)); } finally { setBusy(false); }
  };

  /** Interstitial action — continue into the existing home as-is (drop the chosen name). */
  const continueExisting = async () => {
    if (!pendingToken) return;
    setBusy(true); setErr(null);
    try {
      sessionStorage.removeItem('pendingHomeName');
      await routeAfterIssued(pendingToken, { name: existingName || null, addr: existingAddr });
    } catch (e) { setErr(e instanceof Error ? e.message : String(e)); } finally { setBusy(false); }
  };

  /** Interstitial action — the existing home has NO name: claim the chosen one for it (KMS-signed,
   *  zero prompts), then sign in. One-name-per-SA is enforced by claimName's no-op guard. */
  const claimForExisting = async () => {
    if (!pendingToken || !existingAddr || !chosenName) return;
    setBusy(true); setErr(null);
    try {
      setNote(`Claiming ${chosenName}…`);
      const sign = await signHashFor('email', existingAddr as Address, { token: pendingToken });
      const res = await claimName(existingAddr as Address, sign, chosenName);
      if (!res.ok) throw new Error(res.error);
      sessionStorage.removeItem('pendingHomeName');
      setNote(null);
      await routeAfterIssued(pendingToken, { name: chosenName, addr: existingAddr });
    } catch (e) { setErr(e instanceof Error ? e.message : String(e)); } finally { setBusy(false); }
  };

  return (
    <div style={{ maxWidth: 380 }}>
      {step === 'passkey-offer' ? (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '.6rem' }}>
          <p style={{ fontSize: '.85rem', margin: 0, lineHeight: 1.5 }}>
            <strong>You&rsquo;re in.</strong> Create a passkey so next time this device signs you in with a
            face, fingerprint, or PIN — no emailed code. If it ever stops working, the code always gets you
            back in and you can set a fresh one.
          </p>
          <button className="btn-primary" disabled={busy} onClick={() => void createPasskeyNow()}>
            {busy ? <><span className="spinner" aria-hidden /> Creating…</> : 'Create a passkey'}
          </button>
          <button className="btn-ghost" disabled={busy} onClick={() => void skipPasskey()}>
            Not now — continue with email
          </button>
        </div>
      ) : step === 'existing-home' ? (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '.6rem' }}>
          <p style={{ fontSize: '.85rem', margin: 0, lineHeight: 1.5 }}>
            <strong>{email.trim()}</strong> already opens a home
            {existingName ? <> named <strong>{existingName}</strong></> : <> ({existingAddr ? `${existingAddr.slice(0, 6)}…${existingAddr.slice(-4)}` : 'unnamed'})</>}.
            An email can only ever open its own home, so <strong>{chosenName}</strong> can&rsquo;t be created with it.
          </p>
          {!existingName && chosenName && (
            <button className="btn-primary" disabled={busy} onClick={() => void claimForExisting()}>
              {busy ? <><span className="spinner" aria-hidden /> Naming…</> : `Name that home ${chosenName} and continue`}
            </button>
          )}
          <button className={!existingName && chosenName ? 'btn' : 'btn-primary'} disabled={busy} onClick={() => void continueExisting()}>
            {busy ? <><span className="spinner" aria-hidden /> Opening…</> : `Continue as ${existingName || 'that home'}`}
          </button>
          <button className="btn-ghost" disabled={busy} onClick={() => { setStep('email'); setEmail(''); setOtp(''); setPendingToken(null); setErr(null); setNote(null); }}>
            Use a different email for {chosenName}
          </button>
        </div>
      ) : step === 'email' ? (
        <div style={{ display: 'flex', gap: '.5rem', flexWrap: 'wrap' }}>
          <input
            type="email"
            data-testid="email-auth-input"
            placeholder="you@example.org"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter' && email.trim()) void start(); }}
            style={{ flex: 1, minWidth: 200, padding: '.5rem var(--theme-input-pad-x, .7rem)', border: '1px solid var(--color-border-strong)', borderRadius: 'var(--theme-input-radius, 8px)' }}
          />
          <button className="btn" data-testid="email-auth-continue" disabled={busy || !email.trim()} onClick={() => void start()}>
            {busy ? <><span className="spinner" aria-hidden /> Sending…</> : session ? 'Add email' : 'Continue'}
          </button>
        </div>
      ) : (
        <div style={{ display: 'flex', gap: '.5rem', flexWrap: 'wrap' }}>
          <input
            inputMode="numeric"
            data-testid="email-auth-code"
            placeholder="6-digit code"
            value={otp}
            onChange={(e) => setOtp(e.target.value.replace(/\D/g, '').slice(0, 6))}
            onKeyDown={(e) => { if (e.key === 'Enter' && otp.length === 6) void verify(); }}
            autoFocus
            style={{ width: 130, padding: '.5rem var(--theme-input-pad-x, .7rem)', border: '1px solid var(--color-border-strong)', borderRadius: 'var(--theme-input-radius, 8px)', letterSpacing: '2px' }}
          />
          <button className="btn" data-testid="email-auth-verify" disabled={busy || otp.length !== 6} onClick={() => void verify()}>
            {busy ? <><span className="spinner" aria-hidden /> Checking…</> : 'Verify'}
          </button>
          <button className="btn-ghost" onClick={() => { setStep('email'); setOtp(''); setErr(null); }}>Back</button>
        </div>
      )}
      {busy && <WorkingBar label={step === 'code' ? (note ?? 'Checking your code and opening your home…') : step === 'email' ? 'Sending your code…' : (note ?? 'Working…')} />}
      {!busy && note && <p data-testid="email-auth-note" style={{ fontSize: '.78rem', color: 'var(--color-text-muted)', margin: '.5rem 0 0' }}>{note}</p>}
      {err && <p data-testid="email-auth-error" style={{ fontSize: '.78rem', color: 'var(--color-danger)', margin: '.5rem 0 0' }}>{err}</p>}
    </div>
  );
}
