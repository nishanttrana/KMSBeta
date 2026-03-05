import vectaLogo from "../assets/vecta-logo.svg";

type BrandedLoadingOverlayProps = {
  visible: boolean;
  message?: string;
};

export function BrandedLoadingOverlay({ visible, message }: BrandedLoadingOverlayProps) {
  if (!visible) {
    return null;
  }
  const showMessage = String(message || "").trim().length > 0;

  return (
    <div className="vecta-loading-overlay" aria-live="polite" aria-busy="true">
      <div className={`vecta-loading-card${showMessage ? "" : " vecta-loading-card--compact"}`} role="status">
        <div className="vecta-loading-logo-wrap">
          <svg className="vecta-loading-spinner" viewBox="0 0 56 56">
            <circle className="vecta-loading-spinner-track" cx="28" cy="28" r="24" />
            <circle className="vecta-loading-spinner-arc" cx="28" cy="28" r="24" />
          </svg>
          <img className="vecta-loading-logo" src={vectaLogo} alt="Vecta KMS" />
        </div>
        {showMessage ? <div className="vecta-loading-text">{message}</div> : null}
      </div>
    </div>
  );
}

/**
 * Full-page loading screen shown during initial authentication bootstrap.
 * Enterprise-grade — minimal, professional, no layout shift.
 */
export function InitialLoadingScreen() {
  return (
    <main
      className="vecta-initial-loading"
      role="status"
      aria-live="polite"
      aria-busy="true"
    >
      <div className="vecta-initial-loading-inner">
        <div className="vecta-loading-logo-wrap vecta-loading-logo-wrap--xl">
          <svg className="vecta-loading-spinner vecta-loading-spinner--xl" viewBox="0 0 120 120">
            <circle className="vecta-loading-spinner-track" cx="60" cy="60" r="54" />
            <circle className="vecta-loading-spinner-arc" cx="60" cy="60" r="54" />
          </svg>
          <img className="vecta-loading-logo vecta-loading-logo--xl" src={vectaLogo} alt="Vecta KMS" />
        </div>
        <div className="vecta-initial-loading-label">
          <span>Vecta KMS</span>
        </div>
        <div className="vecta-initial-loading-subtitle">Enterprise Key Management System</div>
        <div className="vecta-initial-loading-bar-track">
          <div className="vecta-initial-loading-bar-fill" />
        </div>
        <div className="vecta-initial-loading-hint">Establishing secure session&hellip;</div>
      </div>
    </main>
  );
}
