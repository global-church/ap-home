import type { Metadata, Viewport } from 'next';
import { Inter } from 'next/font/google';
import './globals.css';
import '../src/components/portal/chat/chat.css';
import '../src/components/portal/settings/settings.css';
import '../src/components/shared/ui/ui.css';
import { GOOGLE_SITE_VERIFICATION, SITE_DESCRIPTION, SITE_KEYWORDS, SITE_ORIGIN } from '../src/seo/site';

// Brand typeface (Inter) exposed as --font-brand; the warm palette + the rest of the
// vertical identity live in app config (whitelabel) + globals.css (ADR-0021).
const inter = Inter({ subsets: ['latin'], variable: '--font-brand', display: 'swap' });

const BRAND = process.env.NEXT_PUBLIC_BRAND_NAME || 'Impact';
// What a search engine and a link preview see (src/seo/site.ts owns the words and the origin). Pages that
// have their own title (/about) extend the template; the portal keeps the front-door title. Indexing is
// decided per path: the front door, /about and /llms.txt are indexable; every other route is stamped
// `X-Robots-Tag: noindex` by next.config from the same list robots.txt disallows.
// The front-door title; a deployment may name it (Global.Church: "GCID — Great Commission ID"). Unset = as before.
const SITE_TITLE = process.env.NEXT_PUBLIC_SITE_TITLE || `${BRAND} — your community portal`;

export const metadata: Metadata = {
  metadataBase: new URL(SITE_ORIGIN),
  title: { default: SITE_TITLE, template: `%s · ${BRAND}` },
  description: SITE_DESCRIPTION,
  keywords: [...SITE_KEYWORDS],
  applicationName: BRAND,
  alternates: { canonical: '/' },
  robots: { index: true, follow: true, googleBot: { index: true, follow: true, 'max-image-preview': 'large', 'max-snippet': -1 } },
  openGraph: { type: 'website', siteName: BRAND, title: SITE_TITLE, description: SITE_DESCRIPTION, url: '/', locale: 'en_US' },
  twitter: { card: 'summary_large_image', title: SITE_TITLE, description: SITE_DESCRIPTION },
  ...(GOOGLE_SITE_VERIFICATION ? { verification: { google: GOOGLE_SITE_VERIFICATION } } : {}),
};

export const viewport: Viewport = {
  width: 'device-width',
  initialScale: 1,
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={inter.variable}>
      <body>{children}</body>
    </html>
  );
}
