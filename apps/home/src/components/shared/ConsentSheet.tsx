'use client';
// App-grant consent — the deliberate, honest "what can this app do" disclosure. The
// can/cannot lists + logo come from REGISTERED white-label config (anti-spoof), passed as
// props by the page. Hard rule: cannotDo must be non-empty (honest disclosure).
import { displayAppDomain, displayAppName } from '../onboarding/org-chooser-label';
import { CheckIcon, XIcon } from './Icons';

export interface ConsentTemplate {
  canDo: string[];
  cannotDo: string[];
  expiryDays?: number;
  /** Drop the "This app cannot" block — only ever set by a client's OWN consent wording
   *  (whitelabel/client-consent.ts), never by a shared template, which must keep disclosing. */
  hideCannotDo?: boolean;
}

export function ConsentSheet({
  title,
  signedInAs,
  signedInBare = false,
  appName,
  appDomain,
  appLogo,
  appDescription,
  template,
  busy = false,
  authorizeLabel,
  declineLabel = 'Not now',
  onAuthorize,
  onDecline,
}: {
  title: string;
  /** Who is authorizing — never "your home" when we have a name or address. */
  signedInAs?: string;
  /** With no `signedInAs`, still say "Signed in" — naming nobody. For a client that never shows an
   *  address or handle (`consent.hideIdentifiers`) while its email is not known. */
  signedInBare?: boolean;
  appName: string;
  appDomain: string;
  appLogo?: string;
  /** One registered line on what the app is for (RelyingApp.description); absent shows nothing. */
  appDescription?: string;
  template: ConsentTemplate;
  busy?: boolean;
  authorizeLabel: string;
  declineLabel?: string;
  onAuthorize: () => void;
  onDecline: () => void;
}) {
  if (process.env.NODE_ENV !== 'production' && !template.hideCannotDo && template.cannotDo.length === 0) {
    throw new Error('ConsentSheet: template.cannotDo must be non-empty (honest disclosure is required).');
  }
  const politeName = displayAppName(appName, appDomain || appName);
  const politeDomain = displayAppDomain(appDomain || '');
  const session = signedInAs?.trim() && !/^your home\.?$/i.test(signedInAs.trim()) ? signedInAs.trim() : '';
  const titleUsesHost = /workers\.dev|pages\.dev|vercel\.app/i.test(title);
  const politeTitle = titleUsesHost ? `Allow ${politeName}?` : title.replace(appName, politeName);
  const ctaUsesHost = /workers\.dev|pages\.dev|vercel\.app/i.test(authorizeLabel);
  const politeCta = ctaUsesHost || authorizeLabel.length > 32 ? `Allow ${politeName}` : authorizeLabel.replace(appName, politeName);
  const initial = (politeName.trim().charAt(0) || '?').toUpperCase();
  const showDomain = Boolean(politeDomain) && politeDomain.toLowerCase() !== politeName.toLowerCase();
  return (
    <div className="consent-sheet">
      {session ? (
        <p className="consent-session">
          Signed in as <strong>{session}</strong>
        </p>
      ) : signedInBare ? (
        <p className="consent-session">Signed in</p>
      ) : null}

      <div className="consent-app">
        {appLogo ? (
          // eslint-disable-next-line @next/next/no-img-element
          <img src={appLogo} alt="" className="consent-app-logo" />
        ) : (
          <div className="consent-app-logo placeholder" aria-hidden="true">{initial}</div>
        )}
        <div>
          <div className="consent-app-name">{politeName}</div>
          {showDomain && <div className="consent-app-domain">{politeDomain}</div>}
          {appDescription && <div className="consent-app-domain">{appDescription}</div>}
        </div>
      </div>

      <h2 className="consent-title">{politeTitle}</h2>

      {template.canDo.length > 0 && (
        <>
          <p className="consent-group">This app can</p>
          <ul className="consent-list can" aria-label="What this app can do">
            {template.canDo.map((c) => (
              <li key={c}><span className="consent-icon ok" aria-hidden="true"><CheckIcon size={14} /></span>{c}</li>
            ))}
          </ul>
        </>
      )}
      {!template.hideCannotDo && (
        <>
          <p className="consent-group">This app cannot</p>
          <ul className="consent-list cannot" aria-label="What this app cannot do">
            {template.cannotDo.map((c) => (
              <li key={c}><span className="consent-icon no" aria-hidden="true"><XIcon size={14} /></span>{c}</li>
            ))}
          </ul>
        </>
      )}

      <p className="consent-expiry">
        {template.expiryDays
          ? `Expires in ${template.expiryDays} days. Revoke anytime from Connected Apps.`
          : 'Ongoing until you revoke it from Connected Apps.'}
      </p>

      <div className="consent-actions">
        <button type="button" className="btn-primary" onClick={onAuthorize} disabled={busy}>
          {busy ? 'Connecting…' : politeCta}
        </button>
        <button type="button" className="btn-ghost" onClick={onDecline} disabled={busy}>
          {declineLabel}
        </button>
      </div>
    </div>
  );
}
