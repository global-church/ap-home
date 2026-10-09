'use client';
// A relying app's OWN look for the sign-in window it opened (whitelabel `RelyingApp.theme`).
//
// The portal Gate wraps a relying app's onboarding screens in this when — and only when — that window
// belongs to a client that registered a theme. The wrapper is `display: contents` (no box, no layout
// change); it only carries the client's CSS variables, which every descendant inherits, so the Home's
// own tokens (globals.css `:root`) are overridden for THIS window and nowhere else. The font sheet is
// fetched only while a themed window is open. No theme → the children, untouched.
import type { CSSProperties, ReactNode } from 'react';
import type { ClientTheme } from '../../whitelabel/config';

export function ClientThemeScope({ theme, children }: { theme: ClientTheme | undefined; children: ReactNode }) {
  if (!theme) return <>{children}</>;
  return (
    <div className={theme.className ? `client-theme ${theme.className}` : 'client-theme'} style={theme.vars as CSSProperties}>
      {theme.fontHref && (
        <>
          <link rel="preconnect" href="https://fonts.googleapis.com" />
          <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="" />
          <link rel="stylesheet" href={theme.fontHref} />
        </>
      )}
      {children}
    </div>
  );
}
