'use client';
// THE ORGANIZATION'S CONTACT EMAIL (Paul, 2026-10-22): shown, never typed over. Changing it sends a code to the new
// address; server/connect/org-contact.ts checks that you manage the organization and that the code is right, and
// keeps GCID's copy. Only then is it written to the organization's own profile (its vault), by `save`.
import { useState, type CSSProperties } from 'react';
import { useSession } from '../../context/session';

const input: CSSProperties = {
  padding: '.5rem .6rem', borderRadius: 8, border: '1px solid var(--c-g200, #e2e8f0)', fontSize: '.85rem', fontFamily: 'inherit', background: '#fff',
};
const small: CSSProperties = { fontSize: '.8rem', padding: '.4rem .8rem' };

export function OrgContactEmail({ org, current, save }: { org: string; current: string; save: (email: string) => Promise<void> }) {
  const { session } = useSession();
  const [step, setStep] = useState<'show' | 'email' | 'code' | 'save'>('show');
  const [email, setEmail] = useState('');
  const [code, setCode] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const address = email.trim().toLowerCase();

  async function call(path: 'start' | 'verify', body: Record<string, string>): Promise<void> {
    const r = await fetch(`/connect/org-contact/${path}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...(session?.token ? { authorization: `Bearer ${session.token}` } : {}) },
      body: JSON.stringify({ org, ...body }),
    }).catch(() => null);
    const j = (await r?.json().catch(() => null)) as { ok?: boolean; error?: string } | null;
    if (!r?.ok || !j?.ok) throw new Error(j?.error ?? 'Something went wrong. Try again.');
  }

  async function sendCode() {
    setBusy(true);
    setErr(null);
    try {
      await call('start', { email: address });
      setCode('');
      setStep('code');
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'The code could not be sent.');
    } finally {
      setBusy(false);
    }
  }

  /** The code is confirmed: write it to the organization. A failure here keeps the confirmed address for a retry. */
  async function store() {
    setBusy(true);
    setErr(null);
    setStep('save');
    try {
      await save(address);
      setStep('show');
      setMsg('Contact email confirmed and saved ✓');
    } catch (e) {
      setErr(`Saving to the organization didn’t finish: ${e instanceof Error ? e.message : 'try again'}`);
    } finally {
      setBusy(false);
    }
  }

  async function confirm() {
    setBusy(true);
    setErr(null);
    try {
      await call('verify', { email: address, otp: code });
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'The code could not be checked.');
      setBusy(false);
      return;
    }
    await store();
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '.35rem', fontSize: '.8rem', color: 'var(--c-g600, #475569)' }} data-testid="org-contact">
      Contact email
      {step === 'show' && (
        <div style={{ display: 'flex', gap: '.6rem', alignItems: 'center', flexWrap: 'wrap' }}>
          <span style={{ fontSize: '.85rem', color: 'var(--c-g800, #1e293b)' }} data-testid="org-contact-current">{current || 'None yet'}</span>
          <button
            type="button"
            className="btn-ghost"
            style={small}
            onClick={() => { setStep('email'); setEmail(''); setMsg(null); setErr(null); }}
            data-testid="org-contact-change"
          >
            {current ? 'Change' : 'Add'}
          </button>
          {msg && <span style={{ color: 'var(--c-success, #16a34a)' }}>{msg}</span>}
        </div>
      )}
      {step === 'email' && (
        <form style={{ display: 'flex', gap: '.5rem', flexWrap: 'wrap' }} onSubmit={(e) => { e.preventDefault(); void sendCode(); }}>
          <input style={{ ...input, flex: '1 1 220px', minWidth: 0 }} type="email" placeholder="office@example.org" value={email} onChange={(e) => setEmail(e.target.value)} autoFocus data-testid="org-contact-email" />
          <button type="submit" className="btn-primary" style={small} disabled={busy || !address.includes('@')}>{busy ? 'Sending…' : 'Send code'}</button>
          <button type="button" className="btn-ghost" style={small} onClick={() => setStep('show')}>Cancel</button>
        </form>
      )}
      {step === 'code' && (
        <form style={{ display: 'flex', gap: '.5rem', flexWrap: 'wrap', alignItems: 'center' }} onSubmit={(e) => { e.preventDefault(); void confirm(); }}>
          <span style={{ flexBasis: '100%' }}>We sent a code to <b>{address}</b>. Enter it to make that this organization&rsquo;s contact email.</span>
          <input style={{ ...input, width: 130 }} inputMode="numeric" maxLength={6} placeholder="6-digit code" value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))} autoFocus data-testid="org-contact-code" />
          <button type="submit" className="btn-primary" style={small} disabled={busy || code.length !== 6} data-testid="org-contact-verify">{busy ? 'Checking…' : 'Confirm'}</button>
          <button type="button" className="btn-ghost" style={small} onClick={() => void sendCode()} disabled={busy}>Send again</button>
          <button type="button" className="btn-ghost" style={small} onClick={() => setStep('show')} disabled={busy}>Cancel</button>
        </form>
      )}
      {step === 'save' && !busy && (
        <div style={{ display: 'flex', gap: '.5rem', alignItems: 'center', flexWrap: 'wrap' }}>
          <span>The code for <b>{address}</b> is confirmed.</span>
          <button type="button" className="btn-primary" style={small} onClick={() => void store()}>Try saving again</button>
        </div>
      )}
      {err && <span style={{ color: 'var(--c-danger, #dc2626)' }}>{err}</span>}
    </div>
  );
}
