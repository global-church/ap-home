// The email a person verified (6-digit code) IN THIS WINDOW, remembered for the rest of the same window.
//
// A relying app's consent screen names the person by their email ("Signed in as host@church.org"). Reading
// it back off their vault profile takes a round trip that can lose a 5 s race, which left the line saying
// `0x8bca…3807` instead. But the person typed and verified that email a few seconds earlier, in this very
// window — so the code step leaves it here and the consent screen reads it first.
//
// sessionStorage: per tab, same origin, gone when the window closes. Keyed by the home's address so a
// later sign-in as somebody else in the same tab never shows the previous person's email. Display only:
// it is never sent anywhere and authorizes nothing.
const KEY = 'verifiedEmail';

export function rememberVerifiedEmail(address: string | null | undefined, email: string): void {
  if (!address || !email.includes('@')) return;
  try {
    sessionStorage.setItem(KEY, JSON.stringify({ address: address.toLowerCase(), email: email.trim().toLowerCase() }));
  } catch {
    /* storage unavailable — the profile read still runs */
  }
}

export function verifiedEmailFor(address: string | null | undefined): string {
  if (!address) return '';
  try {
    const raw = sessionStorage.getItem(KEY);
    if (!raw) return '';
    const v = JSON.parse(raw) as { address?: unknown; email?: unknown };
    return typeof v.address === 'string' && typeof v.email === 'string' && v.address === address.toLowerCase() ? v.email : '';
  } catch {
    return '';
  }
}
