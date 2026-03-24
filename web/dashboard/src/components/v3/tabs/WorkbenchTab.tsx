// @ts-nocheck -- legacy tab: strict typing deferred, do not add new suppressions
import { lazy, Suspense } from "react";

// Each sub-pane is lazy-loaded so only the active one is fetched.
// Previously all 5 were eagerly bundled together (~711 kB chunk).
const CryptoTab        = lazy(() => import("./CryptoTab").then(m => ({ default: m.CryptoTab })));
const RestAPITab       = lazy(() => import("./RestAPITab").then(m => ({ default: m.RestAPITab })));
const TokenizeTab      = lazy(() => import("./TokenizeTab").then(m => ({ default: m.TokenizeTab })));
const DataEncryptionTab = lazy(() => import("./TokenizeTab").then(m => ({ default: m.DataEncryptionTab })));
const PaymentTab       = lazy(() => import("./PaymentTab").then(m => ({ default: m.PaymentTab })));

const SubFallback = <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: 200, fontSize: 12, color: "#888" }}>Loading...</div>;

export const WorkbenchTab = ({ session, keyCatalog, onToast, subView, fipsMode }) => {
  const active = String(subView || "crypto");
  return (
    <Suspense fallback={SubFallback}>
      {active === "restapi"  && <RestAPITab session={session} keyCatalog={keyCatalog} onToast={onToast} />}
      {active === "tokenize" && <TokenizeTab session={session} keyCatalog={keyCatalog} onToast={onToast} />}
      {active === "dataenc"  && <DataEncryptionTab session={session} keyCatalog={keyCatalog} onToast={onToast} />}
      {active === "payment"  && <PaymentTab session={session} keyCatalog={keyCatalog} onToast={onToast} />}
      {active !== "restapi" && active !== "tokenize" && active !== "dataenc" && active !== "payment" && (
        <CryptoTab session={session} keyCatalog={keyCatalog} onToast={onToast} fipsMode={fipsMode} />
      )}
    </Suspense>
  );
};
