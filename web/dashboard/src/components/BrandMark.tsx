import { useId } from "react";

// The Vecta mark: a V holding a keyed core. This is its one source in the
// app (sidebar, sign-in, loaders); public/favicon.svg and the first-paint
// splash in index.html repeat the same two shapes.
export function BrandMark({ size = 28, live = false }: { size?: number; live?: boolean }) {
  const id = useId();
  return (
    <svg className={`vk-mark${live ? " vk-mark--live" : ""}`} width={size} height={size} viewBox="0 0 32 32" fill="none" aria-hidden="true">
      <defs>
        <linearGradient id={id} x1="12" y1="4" x2="20" y2="12" gradientUnits="userSpaceOnUse">
          <stop stopColor="var(--c-aurora-from)" />
          <stop offset="1" stopColor="var(--c-aurora-to)" />
        </linearGradient>
      </defs>
      <path className="vk-mark-v" pathLength={1} d="M6 7.5 16 26 26 7.5" stroke="currentColor" strokeWidth="4" strokeLinecap="round" strokeLinejoin="round" />
      <path className="vk-mark-core" d="M16 4.6 19.4 8 16 11.4 12.6 8Z" fill={`url(#${id})`} stroke={`url(#${id})`} strokeWidth="1.6" strokeLinejoin="round" />
    </svg>
  );
}

export function Wordmark({ size = 15 }: { size?: number }) {
  return (
    <span style={{ fontSize: size, fontWeight: 600, letterSpacing: 0.1, color: "var(--c-text)", whiteSpace: "nowrap" }}>
      Vecta <span style={{ color: "var(--c-muted)", fontWeight: 500 }}>KMS</span>
    </span>
  );
}
