// The brand shield mark. Amber gradient in the portal (the warm faith identity); a
// `generic` indigo variant remains available for the neutral external-popup context
// (design §2.6). The wordmark/brand name itself is white-label config, supplied separately.
type Variant = 'brand' | 'generic';

const STOPS: Record<Variant, [string, string, string]> = {
  brand: ['#fbbf24', '#f59e0b', '#d97706'],
  generic: ['#818cf8', '#4338ca', '#3730a3'],
};

export function BrandShield({ size = 28, variant = 'brand' }: { size?: number; variant?: Variant }) {
  const id = `shield-${variant}`;
  const [a, b, c] = STOPS[variant];
  return (
    <svg width={size} height={(size * 46) / 40} viewBox="0 0 40 46" fill="none" aria-hidden="true">
      <defs>
        <linearGradient id={id} x1="0" y1="0" x2="1" y2="1">
          {/* The brand stops are CSS variables with the amber as the fallback, so a relying app's own
              look (whitelabel RelyingApp.theme) can tint the mark inside its window; unset = amber, as before. */}
          <stop offset="0%" style={{ stopColor: variant === 'brand' ? `var(--shield-stop-a, ${a})` : a }} />
          <stop offset="50%" style={{ stopColor: variant === 'brand' ? `var(--shield-stop-b, ${b})` : b }} />
          <stop offset="100%" style={{ stopColor: variant === 'brand' ? `var(--shield-stop-c, ${c})` : c }} />
        </linearGradient>
      </defs>
      <path
        d="M20 1.5 3 8.2v13.4C3 32.4 11 39.8 20 44.5c9-4.7 17-12.1 17-22.9V8.2L20 1.5Z"
        fill={`url(#${id})`}
      />
      <path d="M13.5 22.5 18 27l9-9" stroke="#fff" strokeWidth="3.2" strokeLinecap="round" strokeLinejoin="round" fill="none" />
    </svg>
  );
}
