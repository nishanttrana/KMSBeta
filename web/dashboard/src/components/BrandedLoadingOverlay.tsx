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
          <span className="vecta-loading-pulse" />
          <img className="vecta-loading-logo" src={vectaLogo} alt="Vecta KMS" />
        </div>
        {showMessage ? <div className="vecta-loading-text">{message}</div> : null}
      </div>
    </div>
  );
}
