import { BrandMark } from "./BrandMark";

type BrandedLoadingOverlayProps = {
  visible: boolean;
  message?: string;
};

export function BrandedLoadingOverlay({ visible, message }: BrandedLoadingOverlayProps) {
  if (!visible) {
    return null;
  }
  const text = String(message || "").trim();

  return (
    <div className="vecta-loading-overlay" aria-live="polite" aria-busy="true">
      <div className="vecta-loading-card" role="status" aria-label={text || "Loading"}>
        <BrandMark size={22} live />
        {text ? <div className="vecta-loading-text">{text}</div> : null}
      </div>
    </div>
  );
}

/**
 * Full-page screen shown while the session is restored. It has the same
 * markup as the first-paint splash in index.html, so the two don't jump.
 */
export function InitialLoadingScreen() {
  return (
    <main className="vk-boot" role="status" aria-live="polite" aria-busy="true" aria-label="Loading Vecta KMS">
      <BrandMark size={56} live />
      <div className="vk-boot-name">Vecta <span>KMS</span></div>
      <div className="vk-boot-track"><div className="vk-boot-fill" /></div>
    </main>
  );
}
