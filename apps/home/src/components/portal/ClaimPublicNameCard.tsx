'use client';
// spec 257 (greenfield 08) — the deferred, OPTIONAL "Claim your public name" card. With TRUE
// name-deferral (Phase 1.5), a first-time Google member is deployed NAMELESS during onboarding (no
// name typed OR assigned, subregistry slot left FREE). Their PUBLIC name is offered here, LATER, as
// a desirable card: "a name others can find and link to — your agent's public home", with the
// <handle>.impact-agent.me preview. Dismissible/skippable — the member already has a private home;
// the public name is optional.
//
// ADR-0010: the name is a FACET pointing AT the canonical SA, NEVER part of the SA salt. Claiming a
// custom name does NOT change the SA address — only which name resolves to it. Delegations,
// balances, and the address are untouched.
//
// Wiring: this calls the EXISTING `claimName` primitive (connect-client) with a signHash for the
// member's CURRENT credential (signHashFor) — display/flow only, no custody logic added here. With
// the slot free, the claim genuinely lands (no `AlreadyClaimed`).
//
// REMAINING LIMITATION (one-name-per-caller, contract-level): once a member HOLDS a name (they
// already claimed one here, or a legacy/named home), changing it needs a subregistry rename/release
// (a future contract change). So the `hasName` branch shows the current handle and states that
// changing it isn't available yet — an honest message, not a silent failure (ADR-0013). The common
// fresh-Google member arrives nameless and hits the claim branch. Dismissible either way.
import { useState } from 'react';
import type { Address } from '@agenticprimitives/types';
import { claimName, fetchProfile } from '../../connect-client';
import { notifyAgentsChanged } from './ManagedAgents';
import { resolveVia, signHashFor, publishSocialConnectionKindIfNeeded } from '../../home/onboarding';
import type { Via } from '../../home/onboarding';
import { useSession } from '../../context/session';
import { CONNECT_DOMAIN, nameLabel, CLAIMABLE_TLDS, AGENT_NAME_PARENT } from '../../lib/domain';
import { whitelabel } from '../../whitelabel/config';

const DISMISS_KEY = 'agenticprimitives:demo-sso:claim-name-dismissed';

/** Map the session's `via` (which may be 'Google' | 'passkey' | 'wallet' | 'Wallet') to the
 *  credential `Via` signHashFor expects. */
function viaForSession(via: string | undefined): Via {
  // Every custody kind, not three of them: an email or phone home is KMS-custodied and must never be
  // sent to a passkey prompt (the same fix as client-defaults, 2026-09-13).
  return resolveVia(undefined, via);
}

export function ClaimPublicNameCard() {
  const { session, agentName, agentAddress, refreshProfile } = useSession();
  const brandName = whitelabel.brand.name;
  // Dismissed for this browser? Keep it skippable + sticky-dismissible.
  const [dismissed, setDismissed] = useState<boolean>(() => {
    try {
      return localStorage.getItem(DISMISS_KEY) === '1';
    } catch {
      return false;
    }
  });
  const currentLabel = agentName ? nameLabel(agentName) : '';
  // The member already holds a (forced-unique) name → the subregistry slot is taken, so a custom
  // claim would revert. Surface the current public handle as informational instead of an input.
  const hasName = !!currentLabel;
  const [value, setValue] = useState('');
  const [phase, setPhase] = useState<'idle' | 'claiming' | 'done' | 'error'>('idle');
  const [step, setStep] = useState('');
  const [err, setErr] = useState('');
  const [claimedName, setClaimedName] = useState('');
  // spec 346 — a person home claims `.me` when this deployment's chain has the typed roots
  // (NEXT_PUBLIC_CLAIMABLE_TLDS lists them); otherwise the legacy parent. Never a silent mix.
  const typedPerson = CLAIMABLE_TLDS.includes('me');
  const [tld, setTld] = useState<string>(typedPerson ? 'me' : AGENT_NAME_PARENT);
  const label = nameLabel(value);

  if (dismissed || phase === 'done') {
    if (phase === 'done') {
      return (
        <div className="dash-section" style={{ marginTop: '1.5rem' }}>
          <div className="agent-identity-card standard live">
            <div className="agent-identity-name">{claimedName}</div>
            <div className="agent-identity-sub">Your public name is claimed — others can find and link to it.</div>
          </div>
        </div>
      );
    }
    return null;
  }

  function dismiss() {
    try {
      localStorage.setItem(DISMISS_KEY, '1');
    } catch {
      /* storage blocked — just hide for this view */
    }
    setDismissed(true);
  }

  async function claim() {
    if (!label || !agentAddress || !session) return;
    setPhase('claiming');
    setErr('');
    try {
      const via = viaForSession(session.via);
      const signHash = await signHashFor(via, agentAddress as Address, { token: session.token });
      const res = await claimName(agentAddress as Address, signHash, label, (s) => setStep(s), undefined, tld === AGENT_NAME_PARENT ? {} : { tld });
      if (!res.ok) {
        setErr(res.error);
        setPhase('error');
        return;
      }
      setClaimedName(res.name);
      setPhase('done');
      // spec 280 carve-out — a social home that just claimed its public name publishes its connection KIND
      // so it's signable on a fresh device (no-op for wallet/passkey; kind-only; best-effort).
      void publishSocialConnectionKindIfNeeded(agentAddress as Address, res.name, via, { token: session.token });
      // The reverse-resolve can lag the RPC read replica — poll until the name is visible, then
      // commit + nudge every agents dropdown (same fix as the naming page's claim card).
      void (async () => {
        for (let i = 0; i < 10; i++) {
          const p = await fetchProfile(session.token, { fresh: true }).catch(() => null);
          if (p?.name) break;
          await new Promise((r) => setTimeout(r, 1500));
        }
        await refreshProfile();
        notifyAgentsChanged();
      })();
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'could not claim that name');
      setPhase('error');
    }
  }

  return (
    <div className="dash-section" style={{ marginTop: '1.5rem' }}>
      <div className="agent-identity-card standard">
        <h2 style={{ marginTop: 0 }}>Claim your public name</h2>
        <p className="onboarding-sub">
          A name others can find and link to — your {brandName} agent&apos;s public home.
        </p>

        {hasName ? (
          // Already-named (the W4 auto-name case): show the current public handle. Changing it to a
          // custom name isn't available in this interim (one-name-per-caller; see file header).
          <>
            <div className="name-chip" style={{ marginTop: '.5rem' }}>
              <span className="name-chip-label">{currentLabel}</span>
              <span className="name-chip-full">{currentLabel}.{CONNECT_DOMAIN}</span>
            </div>
            <p className="onboarding-note">
              This is your public name today. Choosing a different one isn&apos;t available yet — your
              private home works regardless of the name.
            </p>
            <button className="btn-ghost onboarding-secondary" onClick={dismiss}>
              Got it — hide this
            </button>
          </>
        ) : phase === 'claiming' ? (
          <div className="onboarding-busy">
            <span className="spinner spinner-lg" role="status" aria-label="Claiming your name" />
            <p className="onboarding-busy-msg">{step || 'Claiming your name…'}</p>
          </div>
        ) : (
          // No name yet → let the member claim one (claimName works; the slot is free).
          <>
            <input
              className="onboarding-input"
              value={value}
              onChange={(e) => setValue(e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, ''))}
              placeholder="e.g. rich-pedersen"
              aria-label="Your public name"
              autoCapitalize="none"
              spellCheck={false}
            />
            {label && (
              <div className="name-chip" style={{ marginTop: '.5rem' }}>
                <span className="name-chip-full">{label}.{CONNECT_DOMAIN}</span>
              </div>
            )}
            {phase === 'error' && <p className="onboarding-hint taken">{err}</p>}
            <button className="btn-primary" disabled={!label || !agentAddress} onClick={claim}>
              Claim this name
            </button>
            <button className="btn-ghost onboarding-secondary" onClick={dismiss}>
              Skip — you already have a private home; the name is optional.
            </button>
          </>
        )}
      </div>
    </div>
  );
}
